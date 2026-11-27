// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nftguard"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"golang.org/x/sys/unix"
)

type registeredSamba struct {
	mu            sync.Mutex
	storage       *registeredStorage
	volumes       *mountowner.MountedVolumeSet
	policy        *naspolicystore.Lease
	identity      *identityowner.FileServiceLease
	candidate     fileserviceplan.SambaIsolatedCandidate
	verifyState   func() error
	network       *os.File
	privatePath   string
	privateInfo   os.FileInfo
	sharePath     string
	handoff       *mountowner.ServiceHandoff
	shares        *mountowner.ServiceSharePins
	configuration *runtimebundle.SambaConfiguration
	daemon        *processowner.SambaDaemon
	started       bool
	stopped       bool
	closed        bool
	review        error
}

type registeredSambaGrants struct {
	policy      *naspolicystore.Owner
	identity    *identityowner.Owner
	backend     smbprovision.Backend
	storage     *registeredStorage
	state       *rc0SambaState
	verifyState func() error
	endpoint    rc0ServiceEndpoint
	authorize   func(context.Context) error
}

func prepareRegisteredSamba(ctx context.Context, g registeredSambaGrants) (_ *registeredSamba, result error) {
	if ctx == nil || ctx.Err() != nil || !safeRC0RunDirectory() || !g.endpoint.valid() ||
		g.policy == nil || g.identity == nil || g.backend == nil || g.storage == nil ||
		g.state == nil || g.verifyState == nil || g.authorize == nil {
		return nil, errRC0Review
	}
	if err := g.verifyState(); err != nil {
		return nil, err
	}
	document, err := g.policy.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if len(document.FileServices.Shares.Shares) == 0 {
		return nil, errRC0Review
	}
	s := &registeredSamba{storage: g.storage, verifyState: g.verifyState}
	defer func() {
		cause, retained := constructionreview.Rollback(result, s.release)
		if retained {
			result = s.retain(cause)
		}
	}()
	s.policy, err = g.policy.Acquire(ctx, document.Revision)
	if err != nil {
		return nil, err
	}
	identity, err := g.identity.FileServiceSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	s.identity, err = g.identity.RetainSMBFileServiceSnapshot(ctx, identity.Fingerprint, g.backend)
	if err != nil {
		return nil, err
	}
	s.volumes, err = s.storage.Volumes(ctx)
	if err != nil {
		return nil, err
	}
	plan, err := fileserviceplan.BuildFromLeasedNASOwners(ctx, s.policy, 0, s.identity, s.volumes)
	if err != nil {
		return nil, err
	}
	s.candidate, err = plan.SambaIsolatedCandidate()
	if err != nil {
		return nil, err
	}
	if err := s.prepareInputs(ctx, g); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *registeredSamba) prepareInputs(ctx context.Context, g registeredSambaGrants) (result error) {
	const parent = "/run/phantowd/service-handoff"
	for _, path := range []string{filepath.Dir(parent), parent} {
		if err := os.Mkdir(path, 0755); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		var st unix.Stat_t
		if unix.Lstat(path, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR ||
			st.Mode&0022 != 0 || st.Mode&0001 == 0 || st.Uid != 0 {
			return errRC0Review
		}
	}
	var err error
	s.privatePath, err = os.MkdirTemp(parent, "rc0-samba.")
	if err != nil {
		return err
	}
	if err := os.Chown(s.privatePath, 0, 0); err != nil {
		return err
	}
	s.privateInfo, err = os.Lstat(s.privatePath)
	if err != nil {
		return err
	}
	root := filepath.Join(s.privatePath, "shares")
	if err := os.Mkdir(root, 0700); err != nil {
		return err
	}
	s.sharePath = root
	if err := errors.Join(os.Chown(root, 0, 0), os.Chmod(root, 0700)); err != nil {
		return err
	}
	s.handoff, s.shares, err = s.candidate.MountPrivateShareRoots(ctx, root, s.volumes)
	if err != nil {
		return err
	}
	s.configuration, err = runtimebundle.StageSambaServiceConfiguration(ctx, s.candidate, g.endpoint.Address)
	if err != nil {
		return err
	}
	config, err := s.configuration.DuplicateRoot(ctx)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, config.Close()) }()
	declaration, err := runtimebundle.SealSambaLaunchDeclaration(s.candidate)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, declaration.Close()) }()
	roots, err := s.shares.DuplicateRoots()
	if err != nil {
		return err
	}
	defer func() {
		for _, role := range roots {
			result = errors.Join(result, role.File.Close())
		}
	}()
	files, err := sambaLaunchRoots(s.candidate, roots)
	if err != nil {
		return err
	}
	filter, err := s.openIngress(ctx, g.endpoint)
	if err != nil {
		if filter != nil {
			err = errors.Join(err, filter.Close(context.WithoutCancel(ctx)))
		}
		return err
	}
	s.daemon, err = processowner.NewSambaDaemon(g.endpoint.Address, declaration, config,
		g.state.roles[0], g.state.roles[1], files, filter, g.authorize)
	if err != nil {
		return errors.Join(err, filter.Close(context.WithoutCancel(ctx)))
	}
	return nil
}

func sambaLaunchRoots(candidate fileserviceplan.SambaIsolatedCandidate, roots []mountowner.ServiceShareDescriptor) ([]*os.File, error) {
	_, _, _, _, ordered, err := candidate.Documents()
	if err != nil || len(ordered) != len(roots) {
		return nil, errRC0Review
	}
	byID := make(map[string]mountowner.ServiceShareDescriptor, len(roots))
	for _, root := range roots {
		byID[root.ShareID] = root
	}
	files := make([]*os.File, 0, len(roots))
	for _, grant := range ordered {
		root := byID[grant.ID]
		if root.File == nil || root.ReadOnly != grant.ReadOnly {
			return nil, errRC0Review
		}
		files = append(files, root.File)
		delete(byID, grant.ID)
	}
	return files, nil
}

func (s *registeredSamba) openIngress(ctx context.Context, endpoint rc0ServiceEndpoint) (_ *nftguard.Samba, result error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	link, err := observeLocalNFSLink(ctx, endpoint.Address, endpoint.IngressIndex)
	if err != nil {
		return nil, err
	}
	s.network, err = os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return nil, err
	}
	namespace, err := s.network.Stat()
	if err != nil {
		return nil, err
	}
	domain := func(ctx context.Context) error {
		current, err := os.Stat("/proc/thread-self/ns/net")
		if err != nil || !os.SameFile(namespace, current) {
			return errRC0Review
		}
		observed, err := observeLocalNFSLink(ctx, endpoint.Address, endpoint.IngressIndex)
		if err != nil || observed != link {
			return errRC0Review
		}
		return ctx.Err()
	}
	code, err := openLocalNFSExecutable("/usr/sbin/nft")
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, code.Close()) }()
	var fs unix.Statfs_t
	if unix.Fstatfs(int(code.Fd()), &fs) != nil || fs.Flags&unix.ST_RDONLY == 0 {
		return nil, errRC0Review
	}
	return nftguard.NewSamba(ctx, domain, endpoint.Address, endpoint.IngressIndex, code)
}

func (s *registeredSamba) check(ctx context.Context) error {
	info, err := os.Lstat(s.privatePath)
	if err != nil || info.Mode() != os.ModeDir|0700 || !os.SameFile(s.privateInfo, info) {
		return errRC0Review
	}
	volumes, err := s.storage.Volumes(ctx)
	if err != nil || volumes != s.volumes {
		return errors.Join(errRC0Review, err)
	}
	plan, err := fileserviceplan.BuildFromLeasedNASOwners(ctx, s.policy, 0, s.identity, volumes)
	if err != nil || !s.candidate.FreshAgainst(plan.Freshness()) {
		return errors.Join(errRC0Review, err)
	}
	config, err := s.configuration.DuplicateRoot(ctx)
	if err != nil {
		return err
	}
	return errors.Join(config.Close(), s.verifyState(), s.candidate.VerifyShareRoots(volumes, s.shares))
}

func (s *registeredSamba) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx); err != nil {
		return s.retain(err)
	}
	state, err := s.daemon.Start(ctx)
	if err != nil {
		return err
	}
	s.started = state.State == processowner.StateReady
	if !s.started {
		return s.retain(errRC0Review)
	}
	if err := s.check(ctx); err != nil {
		return s.retain(errors.Join(err, s.daemon.Abort()))
	}
	exited, err := s.daemon.Exited()
	if err != nil {
		return s.retain(errors.Join(err, s.daemon.Abort()))
	}
	select {
	case <-exited:
		return s.retain(s.daemon.Abort())
	default:
	}
	go s.watchExit(ctx, exited)
	return nil
}

func (s *registeredSamba) watchExit(ctx context.Context, exited <-chan struct{}) {
	select {
	case <-ctx.Done():
		return
	case <-exited:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Stop holds this lock through settlement. Its own leader exit is
	// expected, including when a later storage check requires review.
	if !s.stopped && !s.closed && s.review == nil {
		s.retain(s.daemon.Abort())
	}
}

func (s *registeredSamba) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.review != nil {
		return s.review
	}
	if s.stopped {
		return nil
	}
	if !s.started || s.closed {
		return errRC0Review
	}
	state, err := s.daemon.Stop(ctx)
	if err != nil {
		if errors.Is(err, processowner.ErrReviewRequired) {
			return s.retain(err)
		}
		return err
	}
	if state.State != processowner.StateStopped {
		return s.retain(errRC0Review)
	}
	s.stopped = true
	if err := s.check(ctx); err != nil {
		return s.retain(err)
	}
	return nil
}

func (s *registeredSamba) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.review != nil {
		return s.review
	}
	if s.started && !s.stopped {
		return s.retain(s.daemon.Abort())
	}
	if err := s.release(); err != nil {
		return s.retain(err)
	}
	s.closed = true
	return nil
}

func (s *registeredSamba) release() error {
	if s.daemon != nil {
		if err := s.daemon.Close(); err != nil {
			return err
		}
	}
	if s.configuration != nil {
		if err := s.configuration.Close(); err != nil {
			return err
		}
	}
	if s.shares != nil {
		if err := s.shares.Close(); err != nil {
			return err
		}
	}
	if s.handoff != nil {
		if err := s.handoff.Close(); err != nil {
			return err
		}
	}
	for _, path := range []string{s.sharePath, s.privatePath} {
		if path != "" {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
	}
	if s.network != nil {
		if err := s.network.Close(); err != nil {
			return err
		}
	}
	if s.identity != nil {
		if err := s.identity.Release(); err != nil {
			return err
		}
	}
	if s.policy != nil {
		return s.policy.Release()
	}
	return nil
}

func (s *registeredSamba) retain(cause error) error {
	s.review = &registeredSambaReview{lifetime: s, cause: cause}
	return s.review
}

type registeredSambaReview struct {
	constructionreview.Marker
	lifetime *registeredSamba
	cause    error
}

func (r *registeredSambaReview) Error() string {
	return fmt.Sprintf("registered Samba requires review: %s", r.cause)
}
func (r *registeredSambaReview) Unwrap() error { return r.cause }
