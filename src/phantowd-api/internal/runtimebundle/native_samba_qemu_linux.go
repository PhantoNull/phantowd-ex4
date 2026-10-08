//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"golang.org/x/sys/unix"
)

const NativeSambaConfigQEMU = "/run/phantowd-native-samba-root/etc/samba/smb.conf"
const nativeCredentialHandoff = "PHANTOWD_NATIVE_CREDENTIAL_HANDOFF_READY inputs=12 original_config=true original_state=true closed_before_exec=true scope=qemu-only\n"

// SambaCredentialDocumentsQEMU renders fixed fixture settings around the opaque
// native lookup. The constructor independently renders expectations again; a
// caller cannot authorize mutated staged bytes by supplying a different map.
func SambaCredentialDocumentsQEMU(lookup fileserviceplan.SambaEnrollmentLookup) (map[string]string, error) {
	passwd, group, nss, err := lookup.LookupDocuments()
	if err != nil {
		return nil, ErrInvalid
	}
	// The opaque lookup already supplies the complete files-only NSS profile.
	// Reuse the paired renderer's bounded grammar; never append duplicate tables
	// or choose different state/global paths for credential workers.
	return boundedNativeDocumentsQEMU(passwd, group, nss, "")
}

// NativeSambaRuntimeQEMU privately retains one code/configuration/state tuple
// and serializes fixed credential workers and one authentication-only daemon
// experiment. No product startup exists. Pending captures remain owned until
// verified teardown.
type NativeSambaRuntimeQEMU struct {
	owner                      *Owner
	helper                     *os.File
	pending                    *processowner.CaptureOwner
	gate                       chan struct{}
	closed                     bool
	daemonAttempted            bool
	daemonPID                  int
	authPaths                  []string
	clients                    *processowner.PinnedSet
	clientsAttempted           bool
	plannedDataPrepared        bool
	plannedDataAttempted       bool
	plannedExitAttempted       bool
	plannedClient              *processowner.PinnedSet
	plannedClientAttempted     bool
	plannedClientPID           int
	plannedClientStopAttempted bool
	plannedClientStopErr       error
	releaseErr                 error
	workerFailure              *nativeWorkerErrorQEMU
}

func (p *Plan) NewNativeSambaRuntimeQEMU(ctx context.Context, code, configuration, state *os.File, lookup fileserviceplan.SambaEnrollmentLookup) (_ *NativeSambaRuntimeQEMU, result error) {
	return p.newNativeSambaRuntimeQEMU(ctx, code, configuration, state, lookup, nil)
}

func (p *Plan) newNativeSambaRuntimeQEMU(ctx context.Context, code, configuration, state *os.File, lookup fileserviceplan.SambaEnrollmentLookup, roots *[2]*os.File) (_ *NativeSambaRuntimeQEMU, result error) {
	if ctx == nil || code == nil || configuration == nil || state == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := sambaCodeFixtureGuard(); err != nil {
		return nil, err
	}
	documents, err := SambaCredentialDocumentsQEMU(lookup)
	if roots != nil {
		documents, err = SambaNativeDataDocumentsQEMU(lookup)
	}
	if err != nil {
		return nil, err
	}
	files := make([]File, 0, len(documents))
	for name, contents := range documents {
		mode := uint32(0644)
		if name == "samba/smb.conf" {
			mode = 0600
		}
		files = append(files, File{Path: name, Size: int64(len(contents)), Mode: mode, SHA256: sha256.Sum256([]byte(contents))})
	}
	expected, err := newConfigurationPlan(files)
	if err != nil {
		return nil, err
	}
	o, err := p.newSambaCodeLifetimeQEMU(ctx, code)
	if err != nil {
		return nil, err
	}
	r := &NativeSambaRuntimeQEMU{owner: o, gate: make(chan struct{}, 1)}
	defer func() {
		if result != nil {
			result = errors.Join(result, r.Close(context.Background()))
		}
	}()
	o.configuration, err = expected.retain(ctx, configuration)
	if err == nil {
		o.sambaState, err = retainSambaState(ctx, state)
	}
	if err == nil {
		r.helper, err = os.Open(sambaFixtureHelper)
	}
	if err == nil {
		err = staticExecutable(r.helper)
	}
	if err == nil {
		err = r.prepareNativeDaemonQEMU(ctx, roots)
	}
	if err == nil {
		err = r.prepareNativeClientsQEMU()
	}
	if err == nil {
		err = o.revalidate(ctx)
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (r *NativeSambaRuntimeQEMU) enter(ctx context.Context) error {
	if r == nil || r.owner == nil || r.gate == nil || ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case r.gate <- struct{}{}:
		return nil
	default:
		return processowner.ErrBusy
	}
}

// AcceptConfigurationQEMU binds a backend's independently opened config inode
// to the original admitted configuration; it returns no authority descriptor.
func (r *NativeSambaRuntimeQEMU) AcceptConfigurationQEMU(ctx context.Context, configuration *os.File) error {
	if configuration == nil {
		return ErrInvalid
	}
	if err := r.enter(ctx); err != nil {
		return err
	}
	defer func() { <-r.gate }()
	if r.closed || r.owner.review {
		return ErrReviewRequired
	}
	// This is only configuration binding, not launch authority. Execute performs
	// complete code/config/state admission immediately before the worker runs.
	if err := r.owner.configuration.revalidate(ctx); err != nil {
		r.owner.review = true
		return ErrReviewRequired
	}
	original, err := r.owner.configuration.contents.files["samba/smb.conf"].Stat()
	actual, actualErr := configuration.Stat()
	if err != nil || actualErr != nil || !os.SameFile(original, actual) {
		return ErrMismatch
	}
	return nil
}

// ExecuteQEMU accepts only fixed typed fixture operations. Raw stdout is private
// executor input, not an HTTP/JSON/log view. On any uncertain result the runtime
// retains review and never retries or runs another credential operation.
func (r *NativeSambaRuntimeQEMU) ExecuteQEMU(ctx context.Context, operation processowner.NativeSambaOperationQEMU, name string, stdin []byte) ([]byte, error) {
	if err := r.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { <-r.gate }()
	if r.closed || r.owner.review || r.pending != nil {
		return nil, ErrReviewRequired
	}
	input, err := sealedNativeCredentialInputQEMU(stdin)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(r.owner.configuration.contents.root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.Join(err, input.Close())
	}
	root := os.NewFile(uintptr(fd), "native-credential-config-caller")
	config := [5]*os.File{root, r.owner.configuration.contents.files["passwd"], r.owner.configuration.contents.files["group"], r.owner.configuration.contents.files["nsswitch.conf"], r.owner.configuration.contents.files["samba/smb.conf"]}
	var state [7]*os.File
	for index, name := range sambaStateDirectories {
		state[index] = r.owner.sambaState.files[name]
	}
	capture, err := processowner.NewNativeSambaCaptureQEMU(r.helper, input, config, state, operation, name)
	err = errors.Join(err, root.Close(), input.Close())
	if err != nil {
		if capture != nil {
			err = errors.Join(err, capture.Close(context.Background()))
		}
		return nil, err
	}
	r.pending = capture
	// Duplicating inputs above has no command/state effects. Admit the complete
	// retained tuple ONCE here, then recheck it after verified worker teardown.
	if err := r.revalidateNativeRuntimeQEMU(ctx); err != nil {
		r.owner.review = true
		// Close owns the pending unlaunched capture. Retain review and a private
		// cause, but disclose only fixed phase/reason labels, never cause text.
		return nil, r.nativeWorkerFailureQEMU(nativeWorkerAdmissionQEMU, err)
	}
	observed, runErr := capture.Capture(ctx)
	defer clear(observed.Stderr)
	settled, settleErr := capture.Settled(context.Background())
	closeErr := capture.Close(context.Background())
	if !settled || settleErr != nil || closeErr != nil {
		clear(observed.Stdout)
		r.owner.review = true
		return nil, r.nativeWorkerFailureQEMU(nativeWorkerSettlementQEMU, errors.Join(settleErr, closeErr)) // Keep pending and all original authority.
	}
	r.pending = nil
	checkErr := r.revalidateNativeRuntimeQEMU(ctx)
	if runErr != nil || observed.Kind != processowner.CaptureExited || observed.ExitCode != 0 || strings.Count(string(observed.Stderr), nativeCredentialHandoff) != 1 || checkErr != nil {
		clear(observed.Stdout)
		r.owner.review = true
		stage, cause := nativeWorkerResultQEMU, error(ErrMismatch)
		if runErr != nil {
			stage, cause = nativeWorkerExecutionQEMU, runErr
		} else if checkErr != nil {
			stage, cause = nativeWorkerPostAdmissionQEMU, checkErr
		}
		return nil, fmt.Errorf("native credential worker kind=%v exit=%d handoff=%d: %w", observed.Kind, observed.ExitCode, strings.Count(string(observed.Stderr), nativeCredentialHandoff), r.nativeWorkerFailureQEMU(stage, cause))
	}
	return observed.Stdout, nil
}

func (r *NativeSambaRuntimeQEMU) Close(ctx context.Context) error {
	if err := r.enter(ctx); err != nil {
		return err
	}
	defer func() { <-r.gate }()
	if r.releaseErr != nil {
		return errors.Join(ErrReviewRequired, r.releaseErr)
	}
	if r.closed {
		return nil
	}
	if r.plannedClient != nil {
		// Settle every owned group before releasing the additional holder's
		// code pin. Stop uncertainty is terminal at this containing boundary.
		if err := r.stopNativeDaemonQEMU(); err != nil {
			r.owner.review, r.releaseErr = true, err
			r.owner.snapshot.State = processowner.StateReviewRequired
			return errors.Join(ErrReviewRequired, err)
		}
		if err := r.plannedClient.Close(); err != nil {
			r.owner.review, r.releaseErr = true, err
			r.owner.snapshot.State = processowner.StateReviewRequired
			return errors.Join(ErrReviewRequired, err)
		}
		r.plannedClient = nil
	}
	if r.pending != nil {
		settled, err := r.pending.Settled(context.Background())
		if !settled || err != nil {
			return ErrReviewRequired
		}
		if err := r.pending.Close(context.Background()); err != nil {
			return ErrReviewRequired
		}
		r.pending = nil
	}
	var clientErr error
	if r.clients != nil {
		_, clientErr = r.clients.Stop(context.Background())
		if clientErr != nil {
			r.owner.review = true
		}
		if err := r.clients.Close(); err != nil {
			_, daemonErr := r.owner.processes.Stop(context.Background())
			return errors.Join(ErrReviewRequired, clientErr, err, daemonErr)
		}
		r.clients = nil // all client groups settled before any original release
	}
	err := errors.Join(clientErr, r.owner.Close(context.Background()))
	if !r.owner.closed {
		return errors.Join(ErrReviewRequired, err)
	}
	r.closed = true
	// Closed fences every service operation, but terminal cleanup uncertainty
	// must remain observable. Never continue to unrelated resources or retry
	// release after the first error; an errored descriptor may already be closed.
	if err != nil {
		r.owner.review = true
		r.releaseErr = err
		r.owner.snapshot.State = processowner.StateReviewRequired
		return errors.Join(ErrReviewRequired, err)
	}
	if err := r.removeNativeAuthQEMU(); err != nil {
		r.owner.review = true
		r.releaseErr = err
		r.owner.snapshot.State = processowner.StateReviewRequired
		return errors.Join(ErrReviewRequired, err)
	}
	if r.helper != nil {
		if err := r.helper.Close(); err != nil {
			r.owner.review = true
			r.releaseErr = err
			r.owner.snapshot.State = processowner.StateReviewRequired
			return errors.Join(ErrReviewRequired, err)
		}
		r.helper = nil
	}
	return nil
}

func sealedNativeCredentialInputQEMU(data []byte) (reader *os.File, result error) {
	if len(data) > 2*smbprovision.MaxPasswordBytes+2 {
		return nil, ErrInvalid
	}
	fd, err := unix.MemfdCreate("native-credential-input", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	writer := os.NewFile(uintptr(fd), "native-credential-input")
	defer func() {
		if err := writer.Close(); err != nil {
			result = errors.Join(result, err)
			if reader != nil {
				result = errors.Join(result, reader.Close())
				reader = nil
			}
		}
	}()
	if err := writer.Chmod(0600); err != nil {
		return nil, err
	}
	if n, err := writer.Write(data); err != nil || n != len(data) {
		return nil, ErrUnavailable
	}
	if _, err := unix.FcntlInt(writer.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		return nil, err
	}
	readerFD, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(readerFD), "sealed-readonly-native-credential-input"), nil
}
