// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	root     = "/mnt/rc0-state"
	proof    = "/run/rc0-confirmed-policy.json"
	launch   = "/run/rc0-boot-v1.json"
	bootDir  = "/run/phantowd-boot"
	control  = "/run/phantowd-boot-control"
	initHook = "/etc/init.d/S51phantowd-management"
	address  = "127.0.0.1:18443"
	origin   = "https://" + address
	install  = "c71c2ba76bd04d29816335c13c31a380"
	api      = "/usr/bin/phantowd-api"
	tlsRole  = root + "/management-tls.pem"
	tlsProof = "/mnt/.rc0-fixture-tls-confirmation"
	policy   = `{"format":"phantowd-nas-service-config","schema_version":1,"revision":1,"file_services":{"format":"phantowd-file-service-config","schema_version":1,"revision":1,"shares":{"format":"phantowd-share-config","schema_version":1,"revision":1,"volumes":[],"users":[],"shares":[]},"nfs":{"format":"phantowd-nfs-policy","schema_version":1,"revision":1,"volume_revision":1,"exports":[]}},"iscsi":{"format":"phantowd-iscsi-policy","schema_version":1,"revision":1,"volume_revision":1,"backings":[],"targets":[]}}`
)

type bootPlan struct {
	Format         string `json:"format"`
	Installation   string `json:"installation_id"`
	Address        string `json:"listen_address"`
	Origin         string `json:"origin"`
	StateMountID   uint64 `json:"state_mount_id"`
	StateRootInode uint64 `json:"state_root_inode"`
	PolicySHA256   string `json:"policy_sha256"`
	TLSLeafSHA256  string `json:"tls_leaf_sha256"`
}

func main() {
	if err := check(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("PHANTOWD_RC0_SUPERVISOR_READY phase=%s https_login=true tls=local_provisioned policy=confirmed same_file=refused wrong_bytes=refused synthetic_state=true clean_stop=true\n", os.Args[1])
}

func check() error {
	if len(os.Args) != 2 || (os.Args[1] != "seed" && os.Args[1] != "verify" && os.Args[1] != "rotated") {
		return errors.New("guest phase required")
	}
	phase := os.Args[1]
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
	if phase == "seed" {
		if err := errors.Join(runInitHook(ctx, "start"), runtimeAbsent()); err != nil {
			return err
		}
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
	if err := expectRefusal(ctx, current, nil); err != nil {
		return err
	}
	if err := os.WriteFile(proof+".wrong", []byte(policy+"\n"), 0600); err != nil {
		return err
	}
	if err := expectRefusal(ctx, proof+".wrong", nil); err != nil {
		return err
	}
	if phase == "seed" {
		stage := root + "/.management-tls.provisioning"
		if err := os.WriteFile(stage, []byte("interrupted TLS fixture"), 0600); err != nil {
			return err
		}
		if err := expectRefusal(ctx, proof, nil); err != nil {
			return err
		}
		if raw, err := os.ReadFile(stage); err != nil || string(raw) != "interrupted TLS fixture" {
			return errors.New("supervisor failed to preserve staged TLS evidence")
		}
		if err := os.Remove(stage); err != nil {
			return err
		}
		for _, change := range []func(*bootPlan){
			func(p *bootPlan) { p.StateMountID++ },
			func(p *bootPlan) { p.StateRootInode++ },
			func(p *bootPlan) { p.PolicySHA256 = strings.Repeat("0", 64) },
			func(p *bootPlan) { p.TLSLeafSHA256 = strings.Repeat("0", 64) },
		} {
			if err := expectRefusal(ctx, proof, change); err != nil {
				return err
			}
		}
		fmt.Println("PHANTOWD_RC0_BOOT_HANDOFF wrong_mount=refused wrong_inode=refused wrong_policy=refused wrong_tls=refused")
	}
	switch phase {
	case "verify":
		if err = runtimeAbsent(); err == nil {
			err = renewCertificate(ctx, credentials)
		}
	case "rotated":
		err = serveFromInit(ctx, credentials)
	default:
		if err = serve(ctx, phase, credentials, nil); err == nil {
			err = proveInterruptedInitLifetime(ctx)
		}
	}
	if err != nil {
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
	const parent = "/mnt"
	const stage = parent + "/.rc0-state.provisioning"
	const policyInput = "/run/rc0-fixture-initial-policy.json"
	const tlsInput = "/run/rc0-fixture-initial-tls.pem"
	if err := os.Chmod(parent, 0700); err != nil {
		return err
	}
	pair, err := generateCertificate()
	if err != nil {
		return err
	}
	defer clear(pair)
	if err := os.WriteFile(policyInput, []byte(policy), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(tlsInput, pair, 0600); err != nil {
		return err
	}
	defer os.Remove(tlsInput)
	installState := func(publicOrigin, policyFile string, admin []byte) (result error) {
		cmd := exec.CommandContext(ctx, api, "--provision-rc0-state", "--nas-installation-id", install)
		cmd.Env = []string{"PHANTOWD_PUBLIC_ORIGIN=" + publicOrigin}
		cmd.Stdin, cmd.Stderr = bytes.NewReader(admin), os.Stderr
		for _, path := range []string{parent, policyFile, tlsInput} {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer func() { result = errors.Join(result, file.Close()) }()
			cmd.ExtraFiles = append(cmd.ExtraFiles, file)
		}
		return cmd.Run()
	}
	refused := func(publicOrigin, policyFile string, admin []byte) bool {
		var exit *exec.ExitError
		return errors.As(installState(publicOrigin, policyFile, admin), &exit) && ctx.Err() == nil
	}
	if !refused("https://localhost:18443", policyInput, credentials) ||
		!refused(origin, tlsInput, credentials) || !refused(origin, policyInput, []byte(`{}`)) {
		return errors.New("RC0 provisioning accepted invalid TLS, policy or administrator input")
	}
	lockedParent, err := os.Open(parent)
	if err != nil {
		return err
	}
	if err := unix.Flock(int(lockedParent.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.Join(err, lockedParent.Close())
	}
	excluded := refused(origin, policyInput, credentials)
	if err := lockedParent.Close(); err != nil || !excluded {
		return errors.New("RC0 provisioning did not honor parent exclusion")
	}
	for _, path := range []string{stage, root} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return errors.New("invalid provisioning input created state")
		}
	}
	if err := os.Mkdir(stage, 0700); err != nil {
		return err
	}
	if !refused(origin, policyInput, credentials) {
		return errors.New("RC0 provisioning accepted interrupted staging")
	}
	if err := os.Remove(stage); err != nil {
		return errors.New("provisioner failed to retain interrupted staging")
	}
	if err := installState(origin, policyInput, credentials); err != nil {
		return fmt.Errorf("provision RC0 state: %w", err)
	}
	if _, err := os.Lstat(stage); !os.IsNotExist(err) {
		return errors.New("initialized RC0 state retained provisioning staging")
	}
	account := root + "/accounts/accounts.json"
	before, err := os.ReadFile(account)
	if err != nil || !refused(origin, policyInput, credentials) {
		return errors.New("RC0 provisioning did not preserve enrolled state")
	}
	after, err := os.ReadFile(account)
	if err != nil || !bytes.Equal(before, after) {
		return errors.New("repeat provisioning changed the administrator credentials")
	}
	if info, err := os.Stat(tlsRole); err != nil || info.Mode() != 0600 {
		return errors.New("TLS identity lacks private mode")
	}
	if raw, err := os.ReadFile(tlsRole); err != nil || !bytes.Equal(raw, pair) {
		return errors.New("published TLS identity differs")
	}
	fmt.Println("PHANTOWD_RC0_STATE_PROVISION input_refusal=clean concurrent=refused orphan_stage=retained state=published replay=refused roles=admin,policy,tls")
	return nil
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

func generateCertificate() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(12), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	defer clear(keyDER)
	public := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return append(public, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...), nil
}

func renewCertificate(ctx context.Context, credentials []byte) error {
	pair, err := generateCertificate()
	if err != nil {
		return err
	}
	defer clear(pair)
	replace := func(expected string) error {
		cmd := exec.CommandContext(ctx, api, "--replace-rc0-tls", "--expected-tls-certificate", expected)
		cmd.Env = []string{"PHANTOWD_PUBLIC_ORIGIN=" + origin}
		return provision(ctx, cmd, root, pair)
	}
	var previous string
	err = serve(ctx, "verify", credentials, func(current string) error {
		previous = current
		if err := replace(current); err == nil || ctx.Err() != nil {
			return errors.New("TLS replacement was not refused while supervision held the state")
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := replace(strings.Repeat("0", 64)); err == nil || ctx.Err() != nil {
		return errors.New("TLS replacement accepted an unrelated fingerprint or timed out")
	}
	if err := replace(previous); err != nil {
		return fmt.Errorf("TLS replacement: %w", err)
	}
	if info, err := os.Stat(tlsRole); err != nil || info.Mode() != 0600 {
		return errors.New("replacement TLS identity lacks private mode")
	}
	if raw, err := os.ReadFile(tlsRole); err != nil || !bytes.Equal(raw, pair) {
		return errors.New("replacement TLS identity differs")
	}
	if err := replace(previous); err == nil || ctx.Err() != nil {
		return errors.New("stale TLS replacement was not refused")
	}
	fmt.Println("PHANTOWD_RC0_TLS_ROTATION live=refused wrong_fingerprint=refused stale=refused replacement=published")
	fingerprint, err := fixtureCertificateFingerprint(pair)
	if err != nil {
		return err
	}
	if err := os.WriteFile(tlsProof, []byte(fingerprint), 0600); err != nil {
		return err
	}
	return serve(ctx, "replacement", credentials, nil)
}

func fixtureCertificateFingerprint(bundle []byte) (string, error) {
	public, _ := pem.Decode(bundle)
	if public == nil || public.Type != "CERTIFICATE" {
		return "", errors.New("fixture certificate unavailable")
	}
	return fmt.Sprintf("%x", sha256.Sum256(public.Bytes)), nil
}

func command(ctx context.Context, mode, confirmation string, change func(*bootPlan)) (*exec.Cmd, error) {
	state, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	plan, err := prepareBootPlan(state, launch, change)
	if err != nil {
		return nil, errors.Join(err, state.Close())
	}
	grant, err := os.Open(confirmation)
	if err != nil {
		return nil, errors.Join(err, state.Close(), plan.Close())
	}
	cmd := exec.CommandContext(ctx, api, mode)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "PHANTOWD_LISTEN_ADDR=127.0.0.1:1", "PHANTOWD_PUBLIC_ORIGIN=http://127.0.0.1:1"}
	cmd.ExtraFiles = []*os.File{state, plan, grant}
	return cmd, nil
}

func prepareBootPlan(state *os.File, path string, change func(*bootPlan)) (*os.File, error) {
	const mask = unix.STATX_INO | unix.STATX_MNT_ID_UNIQUE
	var st unix.Statx_t
	if err := unix.Statx(int(state.Fd()), "", unix.AT_EMPTY_PATH, mask, &st); err != nil || st.Mask&mask != mask {
		return nil, errors.New("fixture state identity unavailable")
	}
	identity, err := os.ReadFile(tlsRole)
	if err != nil {
		return nil, err
	}
	defer clear(identity)
	fingerprint, err := fixtureCertificateFingerprint(identity)
	if err != nil {
		return nil, err
	}
	plan := bootPlan{
		Format: "phantowd-rc0-boot-v1", Installation: install, Address: address, Origin: origin,
		StateMountID: st.Mnt_id, StateRootInode: st.Ino, PolicySHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(policy))),
		TLSLeafSHA256: fingerprint,
	}
	if change != nil {
		change(&plan)
	}
	data, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, err
	}
	return os.Open(path)
}

func closeBootGrants(cmd *exec.Cmd) error {
	return errors.Join(cmd.ExtraFiles[0].Close(), cmd.ExtraFiles[1].Close(), cmd.ExtraFiles[2].Close())
}

func expectRefusal(ctx context.Context, confirmation string, change func(*bootPlan)) error {
	cmd, err := command(ctx, "--supervise-rc0-boot", confirmation, change)
	if err != nil {
		return err
	}
	output, err := cmd.CombinedOutput()
	if errors.Join(closeBootGrants(cmd), ctx.Err()) != nil || err == nil || !bytes.Contains(output, []byte("RC0 management startup or shutdown requires review")) {
		return errors.New("unexpected supervisor refusal evidence")
	}
	return runtimeAbsent()
}

func runtimeAbsent() error {
	for _, path := range []string{"/run/phantowd-rc0", control} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return errors.New("RC0 runtime authority was retained")
		}
	}
	return nil
}

func runInitHook(ctx context.Context, action string) error {
	cmd := exec.CommandContext(ctx, initHook, action)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func serveFromInit(ctx context.Context, credentials []byte) (result error) {
	if err := os.Mkdir(bootDir, 0700); err != nil {
		return err
	}
	slot := bootDir + "/state"
	if err := os.WriteFile(bootDir+"/policy.json", []byte(policy), 0600); err != nil {
		return err
	}
	if err := rejectSymlinkedInitState(ctx, slot); err != nil {
		return err
	}
	for _, path := range []string{bootDir + "/boot.json", bootDir + "/policy.json", bootDir} {
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	if err := proveInitPublication(ctx); err != nil {
		return err
	}
	withdrawn := false
	defer func() {
		if !withdrawn {
			result = errors.Join(result, withdrawInitGrant(ctx))
		}
	}()
	if err := rejectOccupiedInitListener(ctx); err != nil {
		return err
	}
	if err := runInitHook(ctx, "start"); err != nil {
		return fmt.Errorf("init could not start admitted management: %w", err)
	}
	// Exercise shutdown as soon as startup is acknowledged, before any HTTP I/O.
	if err := errors.Join(runInitHook(ctx, "stop"), runtimeAbsent()); err != nil {
		return fmt.Errorf("init could not stop immediately after startup: %w", err)
	}
	if err := runInitHook(ctx, "start"); err != nil {
		return fmt.Errorf("init could not start after a confirmed stop: %w", err)
	}
	stopped := false
	defer func() {
		if !stopped {
			result = errors.Join(result, runInitHook(ctx, "stop"))
		}
	}()
	var exit *exec.ExitError
	if err := runInitHook(ctx, "start"); !errors.As(err, &exit) || ctx.Err() != nil {
		return errors.New("init accepted a duplicate supervisor")
	}
	if err := withdrawInitGrant(ctx); !errors.As(err, &exit) || ctx.Err() != nil {
		return errors.New("withdrawal was accepted while the managed supervisor was live")
	}
	fingerprint, err := observeHTTPS(ctx, credentials)
	if err != nil {
		return err
	}
	if err := runInitHook(ctx, "stop"); err != nil {
		return fmt.Errorf("init could not confirm management shutdown: %w", err)
	}
	stopped = true
	if err := errors.Join(runtimeAbsent(), runInitHook(ctx, "stop")); err != nil {
		return err
	}
	if conn, err := net.DialTimeout("tcp", address, time.Second); err == nil {
		conn.Close()
		return errors.New("management listener remains open after init stop")
	}
	if err := withdrawInitGrant(ctx); err != nil {
		return fmt.Errorf("withdraw after confirmed shutdown: %w", err)
	}
	withdrawn = true
	if _, err := os.Lstat(bootDir); !os.IsNotExist(err) {
		return errors.New("boot grant remained published after withdrawal")
	}
	if _, err := os.Stat(root + "/accounts/accounts.json"); err != nil {
		return errors.New("withdrawal lost access to the original admitted state")
	}
	fmt.Println("PHANTOWD_RC0_GRANT interrupted=refused self_confirmation=refused wrong_tls=refused duplicate=refused live_withdraw=refused withdraw=confirmed")
	fmt.Println("PHANTOWD_RC0_INIT symlink=refused address_in_use=refused duplicate=refused immediate_stop=confirmed https=verified shutdown=confirmed")
	fmt.Printf("PHANTOWD_RC0_TLS_CERTIFICATE phase=rotated sha256=%s\n", fingerprint)
	return nil
}

func proveInterruptedInitLifetime(ctx context.Context) error {
	if err := publishInitGrant(ctx, proof, nil); err != nil {
		return err
	}
	if err := runInitHook(ctx, "start"); err != nil {
		return err
	}
	if err := terminateInitSupervisor(ctx); err != nil {
		return err
	}
	if info, err := os.Lstat(control); err != nil || info.Mode() != os.ModeDir|0700 {
		return errors.New("interrupted supervisor lost its protected review directory")
	}
	for _, path := range []string{control + "/stop", "/run/phantowd-rc0"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return errors.New("interrupted supervisor kept its live service channel")
		}
	}
	if conn, err := net.DialTimeout("tcp", address, time.Second); err == nil {
		conn.Close()
		return errors.New("interrupted supervisor left a live HTTPS listener")
	}
	var exit *exec.ExitError
	for _, action := range []string{"stop", "start"} {
		if err := runInitHook(ctx, action); !errors.As(err, &exit) || ctx.Err() != nil {
			return fmt.Errorf("init accepted %s after an interrupted lifetime", action)
		}
	}
	if err := withdrawInitGrant(ctx); !errors.As(err, &exit) || ctx.Err() != nil {
		return errors.New("withdraw accepted after an interrupted lifetime")
	}
	if _, err := os.Stat(bootDir + "/state/accounts/accounts.json"); err != nil {
		return errors.New("interrupted supervisor lost its published grant")
	}
	fmt.Println("PHANTOWD_RC0_INIT_REVIEW supervisor_exit=unsolicited listener=closed stop=refused start=refused withdraw=refused grant=retained")
	return nil
}

func terminateInitSupervisor(ctx context.Context) error {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: control + "/stop", Net: "unix"})
	if err != nil {
		return err
	}
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var peer *unix.Ucred
	var peerErr error
	if err := raw.Control(func(fd uintptr) {
		peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || peerErr != nil || peer == nil || peer.Pid <= 1 || peer.Uid != 0 {
		return errors.New("cannot identify the original RC0 init supervisor")
	}
	pidFD, err := unix.PidfdOpen(int(peer.Pid), 0)
	if err != nil {
		return err
	}
	defer unix.Close(pidFD)
	if err := conn.Close(); err != nil {
		return err
	}
	if err := unix.PidfdSendSignal(pidFD, unix.SIGTERM, nil, 0); err != nil {
		return err
	}
	exit := []unix.PollFd{{Fd: int32(pidFD), Events: unix.POLLIN}}
	for ctx.Err() == nil {
		if _, err := unix.Poll(exit, 100); err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		if exit[0].Revents&unix.POLLIN != 0 {
			return nil
		}
	}
	return ctx.Err()
}

func publishInitGrant(ctx context.Context, confirmation string, change func(*bootPlan)) error {
	cmd, err := command(ctx, "--rc0-boot-service=publish", confirmation, change)
	if err != nil {
		return err
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return errors.Join(cmd.Run(), closeBootGrants(cmd))
}

func withdrawInitGrant(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, api, "--rc0-boot-service=withdraw")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func publishProvisionedState(ctx context.Context, parent, confirmation, expectedTLS string) error {
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	proofFile, err := os.Open(confirmation)
	if err != nil {
		return errors.Join(err, dir.Close())
	}
	cmd := exec.CommandContext(ctx, api, "--publish-rc0-state", "--nas-installation-id", install, "--expected-tls-certificate", expectedTLS)
	cmd.Env = []string{"PHANTOWD_LISTEN_ADDR=" + address, "PHANTOWD_PUBLIC_ORIGIN=" + origin}
	cmd.ExtraFiles = []*os.File{dir, proofFile}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return errors.Join(cmd.Run(), dir.Close(), proofFile.Close())
}

func proveInitPublication(ctx context.Context) error {
	const staged = "/run/.phantowd-boot.staging"
	if err := os.Mkdir(staged, 0700); err != nil {
		return err
	}
	var exit *exec.ExitError
	if err := runInitHook(ctx, "start"); !errors.As(err, &exit) || ctx.Err() != nil {
		return errors.New("init ignored interrupted boot staging")
	}
	if err := publishInitGrant(ctx, proof, nil); !errors.As(err, &exit) || ctx.Err() != nil {
		return errors.New("publisher ignored interrupted boot staging")
	}
	if err := os.Remove(staged); err != nil {
		return err
	}
	current := root + "/nas-policy/nas-services.json"
	if err := publishInitGrant(ctx, current, nil); !errors.As(err, &exit) || ctx.Err() != nil {
		return errors.New("publisher accepted the current policy as its own confirmation")
	}
	if err := publishInitGrant(ctx, proof, func(p *bootPlan) {
		p.TLSLeafSHA256 = strings.Repeat("0", 64)
	}); !errors.As(err, &exit) || ctx.Err() != nil {
		return errors.New("publisher accepted the wrong TLS identity")
	}
	return proveProvisionedStatePublication(ctx)
}

func proveProvisionedStatePublication(ctx context.Context) error {
	const parent = "/mnt"
	const staged = parent + "/.rc0-state.provisioning"
	const accountStage = root + "/accounts/.accounts.pending"
	const other = parent + "/alternate"
	fingerprint, err := os.ReadFile(tlsProof)
	if err != nil {
		return err
	}
	confirmedTLS := string(fingerprint)
	refused := func(medium, policyFile, leaf string) bool {
		var exit *exec.ExitError
		return errors.As(publishProvisionedState(ctx, medium, policyFile, leaf), &exit) && ctx.Err() == nil
	}
	if !refused(parent, proof+".wrong", confirmedTLS) || !refused(parent, proof, strings.Repeat("0", 64)) ||
		!refused(parent, root+"/nas-policy/nas-services.json", confirmedTLS) {
		return errors.New("provisioned publisher accepted stale policy, self-confirmation or wrong TLS")
	}
	if err := os.Mkdir(other, 0700); err != nil {
		return err
	}
	if !refused(other, proof, confirmedTLS) {
		return errors.New("provisioned publisher accepted missing state")
	}
	if err := os.Symlink(root, other+"/rc0-state"); err != nil {
		return err
	}
	if !refused(other, proof, confirmedTLS) {
		return errors.New("provisioned publisher followed a state symlink")
	}
	if err := errors.Join(os.Remove(other+"/rc0-state"), os.Remove(other)); err != nil {
		return err
	}
	if err := os.Mkdir(staged, 0700); err != nil {
		return err
	}
	if !refused(parent, proof, confirmedTLS) {
		return errors.New("provisioned publisher ignored interrupted provisioning")
	}
	if err := os.Remove(staged); err != nil {
		return err
	}
	if err := os.WriteFile(accountStage, []byte("interrupted fixture"), 0600); err != nil {
		return err
	}
	if !refused(parent, proof, confirmedTLS) {
		return errors.New("provisioned publisher ignored interrupted administrator state")
	}
	if err := os.Remove(accountStage); err != nil {
		return err
	}
	for _, path := range []string{bootDir, "/run/.phantowd-boot.staging"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return errors.New("refused provisioned state left a boot grant or staging")
		}
	}
	if err := publishProvisionedState(ctx, parent, proof, confirmedTLS); err != nil {
		return fmt.Errorf("publish the provisioned state: %w", err)
	}
	if !refused(parent, proof, confirmedTLS) {
		return errors.New("provisioned publisher accepted a second grant")
	}
	fmt.Println("PHANTOWD_RC0_STATE_PUBLICATION absent=refused symlink=refused staging=refused credentials_pending=refused stale_policy=refused independent_tls=verified grant=published")
	return nil
}

func stageInitBootRecord(slot string) error {
	state, err := os.Open(slot)
	if err != nil {
		return err
	}
	plan, err := prepareBootPlan(state, bootDir+"/boot.json", nil)
	if err != nil {
		return errors.Join(err, state.Close())
	}
	return errors.Join(state.Close(), plan.Close())
}

func rejectSymlinkedInitState(ctx context.Context, slot string) (result error) {
	target := bootDir + "/admitted"
	if err := os.Mkdir(target, 0700); err != nil {
		return err
	}
	if err := unix.Mount(root, target, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	defer func() { result = errors.Join(result, unix.Unmount(target, 0), os.Remove(target)) }()
	if err := stageInitBootRecord(target); err != nil {
		return err
	}
	if err := os.Symlink("admitted", slot); err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.Remove(slot)) }()
	var exit *exec.ExitError
	if err := runInitHook(ctx, "start"); !errors.As(err, &exit) || ctx.Err() != nil {
		return errors.Join(errors.New("init accepted a symlinked state role"), runInitHook(ctx, "stop"))
	}
	return runtimeAbsent()
}

func rejectOccupiedInitListener(ctx context.Context) (result error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, listener.Close()) }()
	var exit *exec.ExitError
	if err := runInitHook(ctx, "start"); !errors.As(err, &exit) || ctx.Err() != nil {
		return errors.Join(errors.New("init accepted an occupied HTTPS listener"), runInitHook(ctx, "stop"))
	}
	return runtimeAbsent()
}

func serve(ctx context.Context, phase string, credentials []byte, during func(string) error) error {
	cmd, err := command(ctx, "--supervise-rc0-boot", proof, nil)
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	startErr := cmd.Start()
	closeErr := closeBootGrants(cmd)
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
	fingerprint, err := observeHTTPS(ctx, credentials)
	if err != nil {
		return err
	}
	if during != nil {
		if err := during(fingerprint); err != nil {
			return err
		}
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	err = errors.Join(cmd.Wait(), runtimeAbsent())
	joined = true
	if err == nil {
		fmt.Printf("PHANTOWD_RC0_TLS_CERTIFICATE phase=%s sha256=%s\n", phase, fingerprint)
	}
	return err
}

func observeHTTPS(ctx context.Context, credentials []byte) (string, error) {
	identity, err := os.ReadFile(tlsRole)
	if err != nil {
		return "", err
	}
	defer clear(identity)
	public, _ := pem.Decode(identity)
	roots := x509.NewCertPool()
	if public == nil || !roots.AppendCertsFromPEM(pem.EncodeToMemory(public)) {
		return "", errors.New("persistent certificate refused")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, Jar: jar}
	fingerprint := ""
	for i := 0; i < 30; i++ {
		response, err := client.Get(origin + "/healthz")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 && response.TLS != nil && len(response.TLS.PeerCertificates) > 0 &&
				bytes.Equal(public.Bytes, response.TLS.PeerCertificates[0].Raw) {
				fingerprint = fmt.Sprintf("%x", sha256.Sum256(response.TLS.PeerCertificates[0].Raw))
			}
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if fingerprint == "" {
		return "", errors.New("supervised HTTPS did not become ready")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/api/v1/auth/login", bytes.NewReader(credentials))
	if err != nil {
		return "", err
	}
	request.Header.Set("Origin", origin)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		return "", fmt.Errorf("secure login reply %d", response.StatusCode)
	}
	response, err = client.Get(origin + "/api/v1/nas-services/configuration")
	if err != nil {
		return "", err
	}
	var observed struct {
		Revision uint64
		Applied  bool
	}
	decodeErr := json.NewDecoder(response.Body).Decode(&observed)
	response.Body.Close()
	if response.StatusCode != 200 || decodeErr != nil || observed.Revision != 1 || observed.Applied {
		return "", fmt.Errorf("policy readback refused %d", response.StatusCode)
	}
	return fingerprint, nil
}
