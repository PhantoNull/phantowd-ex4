// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityrpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
)

const (
	smbRPCVersion    = 2
	smbRPCHeaderSize = 4 + 1 + 1 + 1 + 8 + 2
	smbActionStatus  = 1
	smbActionBegin   = 2
	smbActionStep    = 3
	smbActionSetPass = 4
	smbActionEnable  = 5
)

var smbRPCMagic = [4]byte{'P', 'W', 'D', 'S'}

// SMBRequest is the version-2 local credential channel. Password is encoded
// as raw bounded bytes in a fixed binary frame, never JSON or a process value.
// Enable is a separate revision-checked action and has no password payload.
// CallSMB does not modify or retain caller-owned password memory.
type SMBRequest struct {
	Action    string
	AccountID string
	Revision  uint64
	Password  []byte
}

// SMBOperation is the Owner-bound in-process capability used by the protected
// local channel. Requests select only fixed typed operations, never a backend.
type SMBOperation interface {
	Load(context.Context) (smbprovision.Journal, error)
	Begin(context.Context, uint64) error
	Step(context.Context, uint64) error
	SetPasswordDisabled(context.Context, uint64, []byte) error
	Enable(context.Context, uint64) error
}

func (r SMBRequest) valid() bool {
	if !validAccountID(r.AccountID) {
		return false
	}
	switch r.Action {
	case "status":
		return r.Revision == 0 && len(r.Password) == 0
	case "begin", "step", "enable":
		return r.Revision > 0 && len(r.Password) == 0
	case "set-password-disabled":
		return r.Revision > 0 && smbprovision.ValidPassword(r.Password)
	default:
		return false
	}
}

func validAccountID(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// NewRouterWithSMB binds the credential operation lookup alongside the
// credential-free native identity router. Both resolve only existing,
// authority-owned account IDs; no request chooses an executor or backend.
func NewRouterWithSMB(apiUID uint32, resolveIdentity func(string) Operation, resolveSMB func(string) SMBOperation) (*Server, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || apiUID == 0 || apiUID > 65534 || resolveIdentity == nil || resolveSMB == nil {
		return nil, ErrInvalid
	}
	return &Server{uid: apiUID, resolve: resolveIdentity, resolveSMB: resolveSMB}, nil
}

func (s *Server) executeSMB(ctx context.Context, req SMBRequest) Response {
	fail := func(code string) Response { return Response{Version: smbRPCVersion, Code: code} }
	if s == nil || s.resolveSMB == nil || ctx == nil || ctx.Err() != nil {
		return fail("unavailable")
	}
	op := s.resolveSMB(req.AccountID)
	if op == nil {
		return fail("unavailable")
	}
	if req.Action == "status" {
		journal, err := op.Load(ctx)
		if err != nil {
			return fail(smbErrorCode(err))
		}
		return smbStateResponse(req.AccountID, journal)
	}

	var err error
	switch req.Action {
	case "begin":
		err = op.Begin(ctx, req.Revision)
	case "step":
		err = op.Step(ctx, req.Revision)
	case "set-password-disabled":
		err = op.SetPasswordDisabled(ctx, req.Revision, req.Password)
	case "enable":
		err = op.Enable(ctx, req.Revision)
	default:
		return fail("invalid")
	}
	if err != nil {
		return fail(smbErrorCode(err))
	}
	journal, err := op.Load(ctx)
	if err != nil {
		return fail(smbErrorCode(err))
	}
	return smbStateResponse(req.AccountID, journal)
}

func smbStateResponse(accountID string, journal smbprovision.Journal) Response {
	if journal.Validate() != nil || journal.Account.ID != accountID {
		return Response{Version: smbRPCVersion, Code: "unavailable"}
	}
	return Response{Version: smbRPCVersion, Code: "ok", Revision: journal.Revision, Phase: journal.Phase}
}

func smbErrorCode(err error) string {
	switch {
	case errors.Is(err, smbprovision.ErrConflict), errors.Is(err, identityprovision.ErrConflict):
		return "conflict"
	case errors.Is(err, smbprovision.ErrReview), errors.Is(err, identityprovision.ErrReview):
		return "review"
	case errors.Is(err, smbprovision.ErrPending):
		return "pending"
	case errors.Is(err, smbprovision.ErrInvalid), errors.Is(err, identityprovision.ErrInvalid):
		return "invalid"
	default:
		return "unavailable"
	}
}

func validSMBResponse(response Response) bool {
	switch response.Phase {
	case smbprovision.Reserved:
		return response.Revision == 1
	case smbprovision.CreateIntent:
		return response.Revision == 2
	case smbprovision.DisabledNoPassword:
		return response.Revision == 3
	case smbprovision.PasswordIntent:
		return response.Revision == 4
	case smbprovision.CredentialSetDisabled:
		return response.Revision == 5
	case smbprovision.EnableIntent:
		return response.Revision == 6
	case smbprovision.Enabled:
		return response.Revision == 7
	case smbprovision.ReviewRequired:
		return response.Revision >= 2 && response.Revision <= 7
	default:
		return false
	}
}

func isSMBFrame(data []byte) bool {
	return len(data) >= len(smbRPCMagic) && bytes.Equal(data[:len(smbRPCMagic)], smbRPCMagic[:])
}

func smbActionCode(action string) byte {
	switch action {
	case "status":
		return smbActionStatus
	case "begin":
		return smbActionBegin
	case "step":
		return smbActionStep
	case "set-password-disabled":
		return smbActionSetPass
	case "enable":
		return smbActionEnable
	default:
		return 0
	}
}

func smbActionName(action byte) string {
	switch action {
	case smbActionStatus:
		return "status"
	case smbActionBegin:
		return "begin"
	case smbActionStep:
		return "step"
	case smbActionSetPass:
		return "set-password-disabled"
	case smbActionEnable:
		return "enable"
	default:
		return ""
	}
}

func encodeSMBFrame(request SMBRequest) ([]byte, error) {
	if !request.valid() || len(request.AccountID) > 255 || len(request.Password) > 65535 {
		return nil, ErrInvalid
	}
	bodyLength := smbRPCHeaderSize + len(request.AccountID) + len(request.Password)
	if bodyLength > maxFrame {
		return nil, ErrInvalid
	}
	frame := make([]byte, 4+bodyLength)
	binary.BigEndian.PutUint32(frame[:4], uint32(bodyLength))
	body := frame[4:]
	copy(body[:4], smbRPCMagic[:])
	body[4] = smbRPCVersion
	body[5] = smbActionCode(request.Action)
	body[6] = byte(len(request.AccountID))
	binary.BigEndian.PutUint64(body[7:15], request.Revision)
	binary.BigEndian.PutUint16(body[15:17], uint16(len(request.Password)))
	copy(body[smbRPCHeaderSize:], request.AccountID)
	copy(body[smbRPCHeaderSize+len(request.AccountID):], request.Password)
	return frame, nil
}

func decodeSMBRequest(data []byte) (SMBRequest, error) {
	if !isSMBFrame(data) || len(data) < smbRPCHeaderSize || data[4] != smbRPCVersion {
		return SMBRequest{}, ErrInvalid
	}
	idLength := int(data[6])
	passwordLength := int(binary.BigEndian.Uint16(data[15:17]))
	if idLength == 0 || idLength > 64 || passwordLength > smbprovision.MaxPasswordBytes ||
		len(data) != smbRPCHeaderSize+idLength+passwordLength {
		return SMBRequest{}, ErrInvalid
	}
	action := smbActionName(data[5])
	request := SMBRequest{
		Action: action, AccountID: string(data[smbRPCHeaderSize : smbRPCHeaderSize+idLength]),
		Revision: binary.BigEndian.Uint64(data[7:15]),
		Password: data[smbRPCHeaderSize+idLength:],
	}
	if !request.valid() {
		return SMBRequest{}, ErrInvalid
	}
	return request, nil
}

// CallSMB sends one version-2 credential request to a root Unix peer. It
// never retries: a transport error after dispatch requires a fresh status read.
// The framed payload is zeroed after the write; caller-owned input is untouched.
func CallSMB(ctx context.Context, conn *net.UnixConn, request SMBRequest) (Response, error) {
	if conn == nil {
		return Response{}, ErrChannel
	}
	defer conn.Close()
	if ctx == nil || ctx.Err() != nil || !request.valid() {
		return Response{}, ErrInvalid
	}
	if !peer(conn, 0) {
		return Response{}, ErrChannel
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	frame, err := encodeSMBFrame(request)
	if err != nil {
		return Response{}, err
	}
	defer clear(frame)
	if conn.SetDeadline(deadline) != nil {
		return Response{}, ErrChannel
	}
	n, err := conn.Write(frame)
	clear(frame)
	if err != nil || n != len(frame) {
		return Response{}, ErrChannel
	}
	data, err := receive(conn)
	if err != nil {
		return Response{}, ErrChannel
	}
	defer clear(data)
	var reply Response
	if decodeResponse(data, &reply, smbRPCVersion) != nil || ctx.Err() != nil {
		return Response{}, ErrChannel
	}
	return reply, nil
}
