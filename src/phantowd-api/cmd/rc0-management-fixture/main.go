// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

//go:build linux && qemu

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
	root          = "/mnt/rc0-state"
	proof         = "/run/rc0-confirmed-policy.json"
	launch        = "/run/rc0-boot-v1.json"
	bootDir       = "/run/phantowd-boot"
	control       = "/run/phantowd-boot-control"
	initHook      = "/etc/init.d/S51phantowd-management"
	address       = "127.0.0.1:18443"
	origin        = "https://" + address
	install       = "c71c2ba76bd04d29816335c13c31a380"
	api           = "/usr/bin/phantowd-api"
	tlsRole       = root + "/management-tls.pem"
	identityRole  = root + "/service-identities"
	sambaRole     = root + "/samba-state"
	storageProof  = "/run/rc0-fixture-storage.json"
	storageSource = "/run/phantowd-data-sources/boot-data"
	storageTarget = "/srv/phantowd/volumes/boot-data"
	storageUUID   = "11111111-2222-3333-4444-555555555555"
	policy        = `{"format":"phantowd-nas-service-config","schema_version":1,"revision":1,"file_services":{"format":"phantowd-file-service-config","schema_version":1,"revision":1,"shares":{"format":"phantowd-share-config","schema_version":1,"revision":1,"volumes":[],"users":[],"shares":[]},"nfs":{"format":"phantowd-nfs-policy","schema_version":1,"revision":1,"volume_revision":1,"exports":[]}},"iscsi":{"format":"phantowd-iscsi-policy","schema_version":1,"revision":1,"volume_revision":1,"backings":[],"targets":[]}}`
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
	StorageSHA256  string `json:"storage_sha256"`
}

func main() {
	if err := check(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if strings.HasPrefix(os.Args[1], "nfs-") || strings.HasPrefix(os.Args[1], "smb-") {
		return
	}
	fmt.Printf("PHANTOWD_RC0_SUPERVISOR_READY phase=%s https_login=true tls=local_provisioned policy=confirmed same_file=refused wrong_bytes=refused synthetic_state=true clean_stop=true\n", os.Args[1])
	fmt.Printf("PHANTOWD_RC0_SERVICE_IDENTITIES_READY phase=%s original=true runtime_lock=verified release=verified\n", os.Args[1])
	fmt.Printf("PHANTOWD_RC0_BOOT_STORAGE_READY phase=%s exact_bind=true registry_lock=verified release=verified\n", os.Args[1])
	fmt.Printf("PHANTOWD_RC0_SAMBA_STATE_READY phase=%s original=true runtime_lock=verified release=verified\n", os.Args[1])
}

func check() error {
	if len(os.Args) != 2 {
		return errors.New("guest phase required")
	}
	phase := os.Args[1]
	budget := 45 * time.Second
	if phase == "seed" {
		budget = 60 * time.Second
	}
	if strings.HasPrefix(phase, "smb-") {
		budget = 180 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	switch phase {
	case "smb-client", "smb-legacy-client", "smb-loss-client":
		return smbClient(ctx, phase == "smb-loss-client")
	case "nfs-client":
		return nfsClient(ctx)
	case "seed", "verify", "rotated", "nfs-server", "smb-server", "smb-legacy-server", "smb-loss-server":
	default:
		return errors.New("unknown guest phase")
	}
	secret, err := os.ReadFile("/rc0-fixture/password")
	if err != nil {
		return err
	}
	credentials, err := json.Marshal(map[string]string{"username": "rc0-admin", "password": strings.TrimSpace(string(secret))})
	if err != nil {
		return err
	}
	if phase == "nfs-server" {
		return nfsServer(ctx, credentials)
	}
	if strings.HasPrefix(phase, "smb-") {
		return smbServer(ctx, credentials, bytes.TrimSpace(secret), phase)
	}
	if phase == "seed" {
		if err := errors.Join(runInitHook(ctx, "start"), runtimeAbsent()); err != nil {
			return err
		}
		if err := seed(ctx, credentials, managementPolicy, true); err != nil {
			return err
		}
	}
	if err := os.WriteFile(proof, []byte(managementPolicy), 0600); err != nil {
		return err
	}
	if err := prepareStorageApproval(0); err != nil {
		return err
	}
	current := root + "/nas-policy/nas-services.json"
	if raw, err := os.ReadFile(current); err != nil || string(raw) != managementPolicy {
		return errors.New("persistent policy bytes differ before startup")
	}
	if err := expectRefusal(ctx, current, nil); err != nil {
		return err
	}
	if err := os.WriteFile(proof+".wrong", []byte(managementPolicy+"\n"), 0600); err != nil {
		return err
	}
	if err := expectRefusal(ctx, proof+".wrong", nil); err != nil {
		return err
	}
	if phase == "seed" {
		if err := provisionFixtureISCSICredentials(ctx, secret); err != nil {
			return err
		}
		if err := proveIdentityStartupRefusal(ctx); err != nil {
			return err
		}
		if err := proveSambaStateRefusal(ctx); err != nil {
			return err
		}
		if err := proveStorageStartupRefusal(ctx); err != nil {
			return err
		}
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
			func(p *bootPlan) { p.StorageSHA256 = strings.Repeat("0", 64) },
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
	if raw, err := os.ReadFile(current); err != nil || string(raw) != managementPolicy {
		return errors.New("persistent policy changed during startup")
	}
	if raw, err := os.ReadFile(root + "/accounts/accounts.json"); err != nil || bytes.Contains(raw, bytes.TrimSpace(secret)) {
		return errors.New("credential absent or held plaintext")
	}
	ledger, err := os.ReadFile(identityRole + "/registry/service-accounts.json")
	var identities struct {
		Revision uint64            `json:"revision"`
		FirstID  uint32            `json:"first_id"`
		LastID   uint32            `json:"last_id"`
		Accounts []json.RawMessage `json:"accounts"`
	}
	if err != nil || json.Unmarshal(ledger, &identities) != nil || identities.Revision != 1 ||
		identities.FirstID != 23000 || identities.LastID != 23010 ||
		identities.Accounts == nil || len(identities.Accounts) != 0 {
		return errors.New("original service identities changed across supervision")
	}
	return verifyFixtureISCSICredentials(ctx, secret, phase)
}

func seed(ctx context.Context, credentials []byte, confirmedPolicy string, exerciseManagementRefusals bool) error {
	if err := seedManagementState(ctx, credentials, confirmedPolicy, exerciseManagementRefusals); err != nil {
		return err
	}
	if err := provisionServiceIdentityRange(ctx, `{"first_id":23010,"last_id":23000}`); err == nil || ctx.Err() != nil {
		return errors.New("identity provisioning accepted an invalid range")
	}
	if _, err := os.Lstat(identityRole); !os.IsNotExist(err) {
		return errors.New("invalid allocation published an identity role")
	}
	if err := provisionServiceIdentityRange(ctx, `{"first_id":23000,"last_id":23010}`); err != nil {
		return fmt.Errorf("service identity preparation: %w", err)
	}
	if err := provisionSambaState(ctx); err != nil {
		return fmt.Errorf("Samba state preparation: %w", err)
	}
	registry := root + "/volume-registry"
	if err := os.Mkdir(registry, 0700); err != nil {
		return err
	}
	commit := exec.CommandContext(ctx, api, "--commit-volume-registry", "--expected-registry-revision=0")
	data := fmt.Appendf(nil, `{"format":"phantowd-volume-registry","schema_version":1,"revision":1,"volumes":[{"id":"boot-data","filesystem_uuid":%q}]}`, storageUUID)
	if err := provision(ctx, commit, registry, data); err != nil {
		return err
	}
	return nil
}

func seedManagementState(ctx context.Context, credentials []byte, confirmedPolicy string, exerciseRefusals bool) error {
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
	if err := os.WriteFile(policyInput, []byte(confirmedPolicy), 0600); err != nil {
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
	if !exerciseRefusals {
		return installState(origin, policyInput, credentials)
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

func prepareStorageApproval(ingressIndex int) error {
	return prepareNetworkStorageApproval("nfs", ingressIndex)
}

func prepareNetworkStorageApproval(protocol string, ingressIndex int) error {
	observed, err := storageMount(storageSource)
	if err != nil || observed.Attributes&unix.STATX_ATTR_MOUNT_ROOT == 0 {
		return errors.Join(errors.New("fixture storage source is not mounted"), err)
	}
	// This is independently fixed by the host fixture disk declaration.
	wwn := sha256.Sum256([]byte("phantowd-vpd-observation-v1\x00wwn\x00naa.500f000000000003"))
	data := fmt.Appendf(nil, `{"format":"phantowd-rc0-storage-v1","registry_revision":1,"volumes":[{"id":"boot-data","filesystem_uuid":%q,"mount_id":%d,"root_inode":%d,"device_major":%d,"device_minor":%d,"read_only":false,"disks":[{"wwn_sha256":"%x"}],"arrays":[]}]`,
		storageUUID, observed.Mnt_id, observed.Ino, observed.Dev_major, observed.Dev_minor, wwn)
	if ingressIndex > 0 {
		data = fmt.Appendf(data, `,%q:{"address":%q,"ingress_index":%d}`, protocol, rc0NFSServer, ingressIndex)
	}
	return os.WriteFile(storageProof, append(data, '}'), 0600)
}

func storageMount(path string) (unix.Statx_t, error) {
	const mask = unix.STATX_INO | unix.STATX_MNT_ID_UNIQUE
	var stat unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, mask, &stat); err != nil {
		return stat, err
	}
	if stat.Mask&mask != mask || stat.Attributes_mask&unix.STATX_ATTR_MOUNT_ROOT == 0 {
		return stat, errors.New("fixture storage mount identity unavailable")
	}
	return stat, nil
}

func checkBootStorage(live bool) error {
	source, sourceErr := storageMount(storageSource)
	target, targetErr := storageMount(storageTarget)
	if err := errors.Join(sourceErr, targetErr); err != nil {
		return err
	}
	if mounted := target.Attributes&unix.STATX_ATTR_MOUNT_ROOT != 0; mounted != live {
		return errors.New("storage target did not match boot lifetime")
	}
	if live && (source.Mnt_id == target.Mnt_id || source.Ino != target.Ino ||
		source.Dev_major != target.Dev_major || source.Dev_minor != target.Dev_minor) {
		return errors.New("service storage did not bind the exact approved volume")
	}
	return checkBootRoleLock(root+"/volume-registry", live)
}

func proveStorageStartupRefusal(ctx context.Context) error {
	original, err := os.ReadFile(storageProof)
	if err != nil {
		return err
	}
	stale := bytes.Replace(original, []byte(`"registry_revision":1`), []byte(`"registry_revision":2`), 1)
	if bytes.Equal(original, stale) {
		return errors.New("fixture storage revision was not present")
	}
	if err := os.WriteFile(storageProof, stale, 0600); err != nil {
		return err
	}
	refusal := expectRefusal(ctx, proof, nil)
	return errors.Join(refusal, checkBootStorage(false), os.WriteFile(storageProof, original, 0600))
}

func provisionServiceIdentityRange(ctx context.Context, configuration string) error {
	cmd := exec.CommandContext(ctx, api, "--provision-rc0-service-identities")
	return provision(ctx, cmd, root, []byte(configuration))
}

func proveIdentityStartupRefusal(ctx context.Context) error {
	stage := root + "/.service-identities.provisioning"
	if err := os.WriteFile(stage, []byte("interrupted identity fixture"), 0600); err != nil {
		return err
	}
	if err := expectRefusal(ctx, proof, nil); err != nil {
		return err
	}
	if raw, err := os.ReadFile(stage); err != nil || string(raw) != "interrupted identity fixture" {
		return errors.New("supervisor did not preserve staged service identity evidence")
	}
	if err := os.Remove(stage); err != nil {
		return err
	}
	file, err := os.Open(identityRole)
	if err != nil {
		return err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.Join(err, file.Close())
	}
	return errors.Join(expectRefusal(ctx, proof, nil), file.Close())
}

func checkPersistentServiceLocks(held bool) error {
	err := errors.Join(checkBootRoleLock(identityRole, held), checkBootRoleLock(sambaRole, held))
	if _, statErr := os.Lstat(chapRole); os.IsNotExist(statErr) {
		return err
	}
	return errors.Join(err, checkBootRoleLock(chapRole, held))
}

func provisionSambaState(ctx context.Context) error {
	return provision(ctx, exec.CommandContext(ctx, api, "--provision-rc0-samba-state"), root, nil)
}

func proveSambaStateRefusal(ctx context.Context) error {
	var exit *exec.ExitError
	if err := provisionSambaState(ctx); !errors.As(err, &exit) || ctx.Err() != nil {
		return fmt.Errorf("Samba state accepted a second initialization: %w", err)
	}
	stage := root + "/.samba-state.provisioning"
	if err := os.Mkdir(stage, 0700); err != nil {
		return err
	}
	if err := expectRefusal(ctx, proof, nil); err != nil {
		return err
	}
	if info, err := os.Stat(stage); err != nil || info.Mode() != os.ModeDir|0700 {
		return errors.New("startup lost interrupted Samba state evidence")
	}
	if err := os.Remove(stage); err != nil {
		return err
	}
	private := sambaRole + "/private"
	if err := unix.Mount(private, private, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	refused := expectRefusal(ctx, proof, nil)
	unmounted := unix.Unmount(private, 0)
	if err := errors.Join(refused, unmounted); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_RC0_SAMBA_STATE_REFUSAL duplicate=refused interrupted=refused mount_alias=refused")
	return nil
}

func checkBootRoleLock(path string, held bool) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	lockErr := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	closeErr := file.Close()
	if held && !errors.Is(lockErr, unix.EWOULDBLOCK) || !held && lockErr != nil {
		return errors.Join(errors.New("state role lock did not match supervisor lifetime"), lockErr, closeErr)
	}
	return closeErr
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
	return serve(ctx, "replacement", credentials, nil)
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
	storage, err := os.Open(storageProof)
	if err != nil {
		return nil, errors.Join(err, state.Close(), plan.Close(), grant.Close())
	}
	cmd := exec.CommandContext(ctx, api, mode)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "PHANTOWD_LISTEN_ADDR=127.0.0.1:1", "PHANTOWD_PUBLIC_ORIGIN=http://127.0.0.1:1"}
	cmd.ExtraFiles = []*os.File{state, plan, grant, storage}
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
	public, _ := pem.Decode(identity)
	if public == nil {
		return nil, errors.New("fixture certificate unavailable")
	}
	storage, err := os.ReadFile(storageProof)
	if err != nil {
		return nil, err
	}
	plan := bootPlan{
		Format: "phantowd-rc0-boot-v1", Installation: install, Address: address, Origin: origin,
		StateMountID: st.Mnt_id, StateRootInode: st.Ino, PolicySHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(managementPolicy))),
		TLSLeafSHA256: fmt.Sprintf("%x", sha256.Sum256(public.Bytes)),
		StorageSHA256: fmt.Sprintf("%x", sha256.Sum256(storage)),
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
	var err error
	for _, file := range cmd.ExtraFiles {
		err = errors.Join(err, file.Close())
	}
	return err
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
	if err := os.WriteFile(bootDir+"/policy.json", []byte(managementPolicy), 0600); err != nil {
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
	if err := errors.Join(checkPersistentServiceLocks(true), checkBootStorage(true)); err != nil {
		return err
	}
	// Exercise shutdown as soon as startup is acknowledged, before any HTTP I/O.
	if err := errors.Join(runInitHook(ctx, "stop"), runtimeAbsent(), checkPersistentServiceLocks(false), checkBootStorage(false)); err != nil {
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
	if err := exec.CommandContext(ctx, api, "--rc0-boot-service=stop-nfs-drained").Run(); !errors.As(err, &exit) || ctx.Err() != nil {
		return errors.New("management-only supervisor accepted NFS drain")
	}
	fingerprint, err := observeHTTPS(ctx, credentials)
	if err != nil {
		return err
	}
	if err := errors.Join(checkPersistentServiceLocks(true), checkBootStorage(true)); err != nil {
		return err
	}
	if err := runInitHook(ctx, "stop"); err != nil {
		return fmt.Errorf("init could not confirm management shutdown: %w", err)
	}
	stopped = true
	if err := errors.Join(runtimeAbsent(), runInitHook(ctx, "stop"), checkPersistentServiceLocks(false), checkBootStorage(false)); err != nil {
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
	fmt.Println("PHANTOWD_RC0_NFS_DRAIN management_only=refused https=preserved")
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

func bootSupervisorPID() (int, error) {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: control + "/stop", Net: "unix"})
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var peer *unix.Ucred
	var peerErr error
	if err := raw.Control(func(fd uintptr) {
		peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || peerErr != nil || peer == nil || peer.Pid <= 1 || peer.Uid != 0 {
		return 0, errors.New("cannot identify the original RC0 init supervisor")
	}
	return int(peer.Pid), nil
}

func terminateInitSupervisor(ctx context.Context) error {
	pid, err := bootSupervisorPID()
	if err != nil {
		return err
	}
	pidFD, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return err
	}
	defer unix.Close(pidFD)
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
	unavailable := storageTarget + ".unavailable"
	if err := os.Rename(storageTarget, unavailable); err != nil {
		return err
	}
	refused := publishInitGrant(ctx, proof, nil)
	if err := os.Rename(unavailable, storageTarget); err != nil {
		return err
	}
	if !errors.As(refused, &exit) || ctx.Err() != nil {
		return errors.New("publisher accepted a missing service target")
	}
	if err := publishInitGrant(ctx, proof, nil); err != nil {
		return fmt.Errorf("publish the admitted state: %w", err)
	}
	if err := publishInitGrant(ctx, proof, nil); !errors.As(err, &exit) || ctx.Err() != nil {
		return errors.New("publisher accepted a second grant")
	}
	if err := unix.Mount(storageSource, storageTarget, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	refused = withdrawInitGrant(ctx)
	if err := unix.Unmount(storageTarget, 0); err != nil {
		return err
	}
	if !errors.As(refused, &exit) || ctx.Err() != nil {
		return errors.New("publisher withdrew a storage grant while a service mount remained")
	}
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
	if err := errors.Join(checkPersistentServiceLocks(true), checkBootStorage(true)); err != nil {
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
	err = errors.Join(cmd.Wait(), runtimeAbsent(), checkPersistentServiceLocks(false), checkBootStorage(false))
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
	ready, cancelReady := context.WithTimeout(ctx, 12*time.Second)
	defer cancelReady()
	retry := time.NewTicker(100 * time.Millisecond)
	defer retry.Stop()
	fingerprint := ""
	for {
		request, err := http.NewRequestWithContext(ready, http.MethodGet, origin+"/healthz", nil)
		if err != nil {
			return "", err
		}
		response, err := client.Do(request)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 && response.TLS != nil && len(response.TLS.PeerCertificates) > 0 &&
				bytes.Equal(public.Bytes, response.TLS.PeerCertificates[0].Raw) {
				fingerprint = fmt.Sprintf("%x", sha256.Sum256(response.TLS.PeerCertificates[0].Raw))
			}
			break
		}
		select {
		case <-ready.Done():
			return "", fmt.Errorf("supervised HTTPS did not become ready: %w", errors.Join(ready.Err(), err))
		case <-retry.C:
		}
	}
	cancelReady()
	if fingerprint == "" {
		return "", errors.New("supervised HTTPS presented an unexpected health response or certificate")
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
