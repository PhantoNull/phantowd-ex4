//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsicredentials"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
)

// Fixed synthetic sink only. Nothing is sent to the non-root child/configfs,
// environment/arguments/logs or a listener; protocol auth is a separate fixture.
func (b *fixtureWritableBackend) PrepareCredentials(_ context.Context, peers []iscsicredentials.Credential) error {
	b.prepareCalls++
	if len(peers) != 1 || peers[0].Mode != "chap" || peers[0].InitiatorName != "iqn.2001-04.com.example:fixture-peer" || peers[0].InitiatorUser != "fixture-peer" {
		return ErrInvalid
	}
	var sink bytes.Buffer
	if _, err := peers[0].Incoming.WriteTo(&sink); err != nil || sink.String() != "PublicSyntheticToken1!" {
		return ErrUnavailable
	}
	clear(sink.Bytes())
	b.credentialPeers = append([]iscsicredentials.Credential(nil), peers...)
	return nil
}

func exerciseCredentialWritableFixture(ctx context.Context, owner *writableOwner, backend *fixtureWritableBackend,
	policy *naspolicystore.Owner, secrets *iscsicredentials.Owner, directory, kind string, lease *mountowner.MountedVolumeSetLease) error {
	if owner.credentials == nil || owner.policy == nil {
		return errors.New("consumer missing private credential/policy claim")
	}
	if !errors.Is(secrets.Close(), iscsicredentials.ErrBusy) || !errors.Is(policy.Close(), naspolicystore.ErrBusy) {
		return errors.New("credential/policy source not retained")
	}
	if err := owner.start(ctx); err != nil {
		return err
	}
	if backend.prepareCalls != 1 || len(backend.credentialPeers) != 1 {
		return errors.New("fixed credential consumer not prepared once")
	}
	if err := owner.observe(ctx); err != nil {
		return err
	}
	if kind == "chap-normal" {
		if err := owner.stop(ctx); err != nil {
			return err
		}
		if !owner.released || owner.credentials != nil || owner.policy != nil || !backend.stopWithLiveCredentials || !backend.stopWithLiveReference {
			return errors.New("credential release preceded verified teardown")
		}
		select {
		case <-backend.done:
		default:
			return errors.New("credential release before actual reap")
		}
		if _, err := backend.credentialPeers[0].Incoming.WriteTo(io.Discard); !errors.Is(err, iscsicredentials.ErrClosed) {
			return errors.New("released borrow remained usable")
		}
		return secrets.Close()
	}
	backend.stopFailure = kind == "chap-uncertain"
	if err := mutateFixtureDocument(directory, "chap-secrets.json"); err != nil {
		return err
	}
	if !errors.Is(owner.observe(ctx), ErrReview) {
		return errors.New("restored credential mutation revived consumer")
	}
	if backend.stopCalls != 1 || !backend.stopWithLiveCredentials || !backend.stopWithLiveReference {
		return errors.New("credential stop ordering failed")
	}
	if backend.stopFailure {
		if owner.released || owner.credentials == nil || owner.policy == nil || owner.file == nil {
			return errors.New("uncertain teardown dropped combined credential claims")
		}
		if !errors.Is(secrets.Close(), iscsicredentials.ErrBusy) || !errors.Is(policy.Close(), naspolicystore.ErrBusy) || !errors.Is(lease.Close(), mountowner.ErrBusy) {
			return errors.New("uncertain teardown unfenced source")
		}
		if _, err := backend.credentialPeers[0].Incoming.WriteTo(io.Discard); err != nil {
			return errors.New("uncertain teardown wiped borrow")
		}
		if live, err := backend.running(ctx); err != nil || !live {
			return errors.New("uncertain fixture child not live")
		}
	} else {
		if !owner.released || owner.credentials != nil || owner.policy != nil {
			return errors.New("confirmed drift stop retained claims")
		}
		if _, err := backend.credentialPeers[0].Incoming.WriteTo(io.Discard); !errors.Is(err, iscsicredentials.ErrClosed) {
			return errors.New("drift borrow still usable")
		}
	}
	for _, op := range []func() error{func() error { return owner.start(ctx) }, func() error { return owner.observe(ctx) }, func() error { return owner.stop(ctx) }, owner.close} {
		if !errors.Is(op(), ErrReview) {
			return errors.New("credential review bypassed")
		}
	}
	if backend.prepareCalls != 1 || backend.stopCalls != 1 {
		return errors.New("uncertain credentials retried")
	}
	return nil
}
func emitCredentialWritableMarker() {
	fmt.Println("PHANTOWD_CHAP_BACKING_LIFETIME_READY root_only_store=true fixed_consumer=true actual_mount_owner=true consumer_uid=1000 stop_before_credential_release=true restored_secret_review=true uncertain_retains_credentials_policy_mount_rw=true no_retry=true plaintext_at_rest=true product_activation=false scope=disposable-qemu-only")
}
