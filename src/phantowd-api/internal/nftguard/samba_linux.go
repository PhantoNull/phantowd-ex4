// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nftguard

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

const (
	sambaTable     = "phantowd_smb"
	sambaInput     = "input"
	sambaChainPath = "inet " + sambaTable + " " + sambaInput
	sambaPriority  = -10
)

var ErrReviewRequired = errors.New("Samba ingress requires review")

type sambaPhase uint8

const (
	sambaFresh sambaPhase = iota
	sambaSealed
	sambaPublished
	sambaFenced
	sambaQuarantined
	sambaClosed
	sambaReview
)

// Samba owns direct SMB ingress for one selected IPv4 interface in a network
// domain reserved by the caller. The boot owner stages the filter before the
// daemon binds, publishes after listener admission, and closes it after group
// settlement. Ambiguous filter mutations require an independent review.
type Samba struct {
	mu       sync.Mutex
	self     *Samba
	code     *os.File
	domain   func(context.Context) error
	address  netip.Addr
	index    int
	name     string
	hardware string
	loopback bool
	token    string
	phase    sambaPhase
	handles  []uint64
}

func NewSamba(ctx context.Context, domain func(context.Context) error, address netip.Addr, index int, code *os.File) (*Samba, error) {
	return newSamba(ctx, domain, address, index, code, false)
}

func newSamba(ctx context.Context, domain func(context.Context) error, address netip.Addr, index int, code *os.File, loopback bool) (*Samba, error) {
	if ctx == nil || domain == nil || !address.Is4() || !address.IsGlobalUnicast() || index <= 0 {
		return nil, ErrState
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := domain(ctx); err != nil {
		return nil, err
	}
	device, err := sambaInterface(address, index, loopback)
	if err != nil {
		return nil, err
	}
	pin, err := processowner.RetainExecutable(code)
	if err != nil {
		return nil, err
	}
	f := &Samba{code: pin, domain: domain, address: address, index: index, name: device.Name,
		hardware: device.HardwareAddr.String(), loopback: loopback, token: "phantowd:" + rand.Text()}
	f.self = f
	return f, nil
}

func sambaInterface(address netip.Addr, index int, loopback bool) (*net.Interface, error) {
	device, err := net.InterfaceByIndex(index)
	if err != nil || device.Flags&net.FlagUp == 0 {
		return nil, ErrState
	}
	if (device.Flags&net.FlagLoopback != 0) != loopback ||
		loopback && device.Name != "lo" || !loopback && len(device.HardwareAddr) != 6 {
		return nil, ErrState
	}
	addrs, err := device.Addrs()
	if err != nil {
		return nil, err
	}
	for _, value := range addrs {
		prefix, err := netip.ParsePrefix(value.String())
		if err != nil {
			return nil, err
		}
		if prefix.Addr() == address {
			return device, nil
		}
	}
	return nil, ErrState
}

func (f *Samba) Address() netip.Addr {
	if f == nil || f.self != f {
		return netip.Addr{}
	}
	return f.address
}

func (f *Samba) Stage(ctx context.Context) error {
	return f.change(ctx, sambaFresh, sambaSealed)
}

func (f *Samba) Publish(ctx context.Context) error {
	return f.change(ctx, sambaSealed, sambaPublished)
}

func (f *Samba) CheckStaged(ctx context.Context) error {
	return f.checkPhase(ctx, sambaSealed)
}

func (f *Samba) CheckPublished(ctx context.Context) error {
	return f.checkPhase(ctx, sambaPublished)
}

// Fence rejects incoming SYNs on TCP/445 and preserves established traffic
// on the selected path. Pending and live connections still require drain
// checks from the daemon owner before graceful shutdown.
func (f *Samba) Fence(ctx context.Context) error {
	return f.change(ctx, sambaPublished, sambaFenced)
}

// CheckFenced verifies that the filter still blocks new TCP connections.
// The stop coordinator combines this proof with protocol and transport drain.
func (f *Samba) CheckFenced(ctx context.Context) error {
	return f.checkPhase(ctx, sambaFenced)
}

// Quarantine blocks all ingress to TCP and UDP port 445 after a failed
// daemon lifetime. The verified table stays installed for review.
func (f *Samba) Quarantine(ctx context.Context) error {
	if f == nil || f.self != f || ctx == nil {
		return ErrState
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch f.phase {
	case sambaPublished, sambaFenced:
		return f.changeLocked(ctx, f.phase, sambaQuarantined)
	case sambaQuarantined:
		return f.check(ctx)
	default:
		return ErrReviewRequired
	}
}

func (f *Samba) checkPhase(ctx context.Context, phase sambaPhase) error {
	if f == nil || f.self != f || ctx == nil {
		return ErrState
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.changeLocked(ctx, from, to)
}

func (f *Samba) changeLocked(ctx context.Context, from, to sambaPhase) error {
	if f.phase == sambaReview {
		return ErrReviewRequired
	}
	if f.phase != phase {
		return ErrState
	}
	return f.check(ctx)
}

// Close releases a fresh guard, or removes a sealed or fenced filter after
// the caller proves the original process group has settled.
func (f *Samba) Close(ctx context.Context) error {
	if f == nil || f.self != f || ctx == nil {
		return ErrState
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch f.phase {
	case sambaClosed:
		return nil
	case sambaReview:
		return ErrReviewRequired
	case sambaFresh:
	case sambaSealed, sambaFenced:
		if err := f.check(ctx); err != nil {
			return err
		}
		if _, err := f.run(ctx, "", "delete", "table", "inet", "handle", strconv.FormatUint(f.handles[0], 10)); err != nil {
			return f.review(err)
		}
		if err := f.requireAbsent(ctx); err != nil {
			return f.review(err)
		}
	default:
		return ErrState
	}
	if err := f.code.Close(); err != nil {
		return f.review(err)
	}
	f.phase = sambaClosed
	return nil
}

func (f *Samba) change(ctx context.Context, from, to sambaPhase) error {
	if f == nil || f.self != f || ctx == nil {
		return ErrState
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.phase == sambaReview {
		return ErrReviewRequired
	}
	if f.phase != from {
		return ErrState
	}
	if err := f.check(ctx); err != nil {
		return err
	}
	if _, err := f.run(ctx, f.request(to), "-f", "-"); err != nil {
		return f.review(err)
	}
	handles, err := f.inspect(ctx, to)
	if err != nil || from != sambaFresh && !slices.Equal(handles[:2], f.handles[:2]) {
		return f.review(err)
	}
	f.phase, f.handles = to, handles
	return nil
}

func (f *Samba) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.phase == sambaFresh {
		return f.requireAbsent(ctx)
	}
	handles, err := f.inspect(ctx, f.phase)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || !slices.Equal(handles, f.handles) {
		return f.review(err)
	}
	return nil
}

func (f *Samba) request(phase sambaPhase) string {
	var b strings.Builder
	if phase == sambaSealed {
		fmt.Fprintf(&b, "create table inet %s { comment %q; }\n", sambaTable, f.token)
		fmt.Fprintf(&b, "add chain %s { type filter hook input priority %d; policy accept; }\n", sambaChainPath, sambaPriority)
	} else {
		fmt.Fprintf(&b, "flush chain %s\n", sambaChainPath)
	}
	if phase == sambaFenced {
		fmt.Fprintf(&b, "add rule %s tcp dport 445 tcp flags & syn == syn drop\n", sambaChainPath)
	}
	if phase == sambaPublished || phase == sambaFenced {
		fmt.Fprintf(&b, "add rule %s meta iif %d ip daddr %s tcp dport 445 accept\n", sambaChainPath, f.index, f.address)
	}
	for _, protocol := range []string{"tcp", "udp"} {
		fmt.Fprintf(&b, "add rule %s %s dport 445 drop\n", sambaChainPath, protocol)
	}
	return b.String()
}

func (f *Samba) requireAbsent(ctx context.Context) error {
	out, err := f.run(ctx, "", "-a", "-j", "-n", "list", "tables")
	if err != nil {
		return err
	}
	objects, err := ParseObjects(out)
	if err != nil {
		return err
	}
	return RequireAbsent(objects, "inet", sambaTable)
}

func (f *Samba) inspect(ctx context.Context, phase sambaPhase) ([]uint64, error) {
	out, err := f.run(ctx, "", "-a", "-j", "-n", "list", "table", "inet", sambaTable)
	if err != nil {
		return nil, err
	}
	objects, err := ParseObjects(out)
	if err != nil {
		return nil, err
	}
	want := []Object{
		{"table": Object{"family": "inet", "name": sambaTable, "comment": f.token}},
		{"chain": Object{"family": "inet", "table": sambaTable, "name": sambaInput,
			"type": "filter", "hook": "input", "prio": json.Number(strconv.Itoa(sambaPriority)), "policy": "accept"}},
	}
	tcpPort := Match(Payload("tcp", "dport"), json.Number("445"))
	drop := Object{"drop": nil}
	rule := func(expressions ...any) Object {
		return Object{"rule": Object{"family": "inet", "table": sambaTable, "chain": sambaInput, "expr": expressions}}
	}
	if phase == sambaFenced {
		synBit := json.Number("2")
		syn := Match(Object{"&": []any{Payload("tcp", "flags"), synBit}}, synBit)
		want = append(want, rule(tcpPort, syn, drop))
	}
	if phase == sambaPublished || phase == sambaFenced {
		want = append(want, rule(Match(Object{"meta": Object{"key": "iif"}}, f.name),
			Match(Payload("ip", "daddr"), f.address.String()), tcpPort, Object{"accept": nil}))
	}
	want = append(want, rule(tcpPort, drop), rule(Match(Payload("udp", "dport"), json.Number("445")), drop))
	if len(objects) != len(want) {
		return nil, ErrState
	}
	handles := make([]uint64, len(want))
	for index, entry := range want {
		for kind, fields := range entry {
			handle, err := MatchObject(objects[index], kind, fields.(Object))
			if err != nil {
				return nil, err
			}
			handles[index] = handle
		}
	}
	return handles, nil
}

func (f *Samba) review(err error) error {
	f.phase = sambaReview
	return errors.Join(ErrReviewRequired, err)
}

func (f *Samba) run(ctx context.Context, input string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := f.domain(ctx); err != nil {
		return nil, err
	}
	device, err := sambaInterface(f.address, f.index, f.loopback)
	if err != nil || device.Name != f.name || device.HardwareAddr.String() != f.hardware {
		return nil, errors.Join(ErrState, err)
	}
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	cmd.Args[0], cmd.Dir = "/usr/sbin/nft", "/"
	cmd.Env, cmd.ExtraFiles = []string{"LC_ALL=C"}, []*os.File{f.code}
	cmd.Stdin = strings.NewReader(input)
	cmd.WaitDelay = time.Second
	var output sambaNFTOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		return nil, errors.Join(err, ctx.Err())
	}
	return output.Bytes(), f.domain(ctx)
}

type sambaNFTOutput struct{ bytes.Buffer }

func (o *sambaNFTOutput) Write(data []byte) (int, error) {
	if len(data) > 1<<20-o.Len() {
		return 0, ErrState
	}
	return o.Buffer.Write(data)
}
