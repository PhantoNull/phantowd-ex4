// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

//go:build linux && qemu

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsicredentials"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

const chapRole = root + "/" + iscsicredentials.InitialRole
const chapStage = root + "/" + iscsicredentials.InitialStage
const fixtureTarget = "fixture-target"

var managementPolicy = strings.NewReplacer(
	`"volumes":[]`, fmt.Sprintf(`"volumes":[{"id":"boot-data","filesystem_uuid":%q}]`, storageUUID),
	`"backings":[],"targets":[]`, `"backings":[{
		"id":"fixture-lun-image","volume_id":"boot-data","relative_path":"iscsi/lun.img",
		"capacity_bytes":4096,"block_size":512,"allocation":"preallocated"
	}],"targets":[{
		"id":"fixture-target","name":"iqn.2001-04.example.com:fixture-target","state":"disabled",
		"luns":[{"id":"fixture-lun","number":0,"backing_id":"fixture-lun-image","access":"rw"}],
		"initiators":[{
			"name":"iqn.2001-04.example.com:fixture-peer",
			"authentication":{
				"mode":"mutual-chap","initiator_user":"fixture-peer","initiator_secret_ref":"incoming",
				"target_user":"fixture-target","target_secret_ref":"outgoing"
			},
			"grants":[{"lun_id":"fixture-lun","access":"rw"}]
		}]
	}]`,
).Replace(policy)

func fixtureCHAPValues(seed []byte) (incoming, outgoing string) {
	in := sha256.Sum256(append([]byte("RC0 fixture initiator:"), seed...))
	out := sha256.Sum256(append([]byte("RC0 fixture target:"), seed...))
	return fmt.Sprintf("%x", in), fmt.Sprintf("%x", out)
}

func provisionFixtureISCSICredentials(ctx context.Context, seed []byte) error {
	incoming, outgoing := fixtureCHAPValues(seed)
	input := func(otherRef, otherValue string) []byte {
		return fmt.Appendf(nil, `{"format":"phantowd-chap-credentials","schema_version":1,"revision":1,"entries":[{"ref":"incoming","secret":%q},{"ref":%q,"secret":%q}]}`, incoming, otherRef, otherValue)
	}
	provision := func(confirmation string, contents []byte) (result error) {
		defer clear(contents)
		cmd := exec.CommandContext(ctx, api, "--provision-rc0-iscsi-credentials", "--nas-installation-id", install)
		cmd.Stdin = bytes.NewReader(contents)
		for _, path := range []string{root, confirmation} {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer func() { result = errors.Join(result, file.Close()) }()
			cmd.ExtraFiles = append(cmd.ExtraFiles, file)
		}
		out, err := cmd.CombinedOutput()
		if bytes.Contains(out, []byte(incoming)) || bytes.Contains(out, []byte(outgoing)) {
			return errors.New("credential provisioning emitted private material")
		}
		return err
	}
	refused := func(confirmation string, contents []byte) bool {
		var exit *exec.ExitError
		return errors.As(provision(confirmation, contents), &exit) && ctx.Err() == nil
	}
	if !refused(proof, input("foreign", outgoing)) || !refused(proof, input("outgoing", incoming)) ||
		!refused(root+"/nas-policy/nas-services.json", input("outgoing", outgoing)) {
		return errors.New("credential provisioning accepted foreign references, reused values or its own policy")
	}
	for _, path := range []string{chapRole, chapStage} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return errors.New("invalid credential provisioning created state")
		}
	}
	if err := os.Mkdir(chapStage, 0700); err != nil {
		return err
	}
	if !refused(proof, input("outgoing", outgoing)) {
		return errors.New("credential provisioning accepted an interrupted stage")
	}
	if err := expectRefusal(ctx, proof, nil); err != nil {
		return err
	}
	if err := os.Remove(chapStage); err != nil {
		return errors.New("interrupted credential stage was not retained")
	}
	if err := provision(proof, input("outgoing", outgoing)); err != nil {
		return fmt.Errorf("valid initial credential provisioning failed: %w", err)
	}
	if !refused(proof, input("outgoing", outgoing)) {
		return errors.New("credential provisioning accepted replay")
	}
	pending := chapRole + "/.chap-secrets.pending"
	const sentinel = "unfinished fixture credential update"
	if err := os.WriteFile(pending, []byte(sentinel), 0600); err != nil {
		return err
	}
	if err := expectRefusal(ctx, proof, nil); err != nil {
		return err
	}
	if raw, err := os.ReadFile(pending); err != nil || string(raw) != sentinel {
		return errors.New("unfinished update was not retained")
	}
	if err := os.Remove(pending); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_RC0_ISCSI_PROVISION policy=confirmed mismatch=refused reuse=refused interrupted=retained pending=retained published=true replay=refused")
	return nil
}

type fixtureCHAPConsumer struct {
	incoming, outgoing [32]byte
}

func (c *fixtureCHAPConsumer) PrepareCredentials(_ context.Context, records []iscsicredentials.Credential) error {
	if len(records) != 1 || records[0].Mode != "mutual-chap" {
		return errors.New("unexpected credential roster")
	}
	for _, row := range []struct {
		secret iscsicredentials.Secret
		digest [32]byte
	}{{records[0].Incoming, c.incoming}, {records[0].Outgoing, c.outgoing}} {
		hash := sha256.New()
		if _, err := row.secret.WriteTo(hash); err != nil || !bytes.Equal(hash.Sum(nil), row.digest[:]) {
			return errors.New("credential did not survive unchanged")
		}
	}
	return nil
}

func verifyFixtureISCSICredentials(ctx context.Context, seed []byte, phase string) (result error) {
	if err := checkBootRoleLock(chapRole, false); err != nil {
		return err
	}
	dir, err := os.Open(chapRole)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, dir.Close()) }()
	vault, err := iscsicredentials.OpenDirectory(dir)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, vault.Close()) }()
	settings, err := naspolicy.Decode(strings.NewReader(managementPolicy))
	if err != nil {
		return err
	}
	incoming, outgoing := fixtureCHAPValues(seed)
	consumer := &fixtureCHAPConsumer{incoming: sha256.Sum256([]byte(incoming)), outgoing: sha256.Sum256([]byte(outgoing))}
	claim, err := vault.Acquire(ctx, 1, settings, fixtureTarget, consumer)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, claim.Release()) }()
	if err := claim.Prepare(ctx); err != nil {
		return err
	}
	fmt.Printf("PHANTOWD_RC0_ISCSI_CREDENTIALS phase=%s opaque=true original=true lock_released=true\n", phase)
	return nil
}
