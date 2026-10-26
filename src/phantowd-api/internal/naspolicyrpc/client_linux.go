//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package naspolicyrpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
)

// Client owns one connection. It never dials/reconnects or changes authority.
// An uncertain exchange makes further operations refuse until explicit disposal.
// Config inputs remain caller-owned; do not mutate them concurrently.
type Client struct {
	self           *Client
	conn           net.Conn
	mu             sync.Mutex
	review, closed bool
}

// NewClient transfers a connected root-peer stream only on success. Dialing,
// protected socket provisioning and product process placement are separate.
func NewClient(conn *net.UnixConn) (*Client, error) {
	if conn == nil || !peer(conn, 0) {
		return nil, naspolicystore.ErrInvalid
	}
	return newClient(conn), nil
}

func newClient(conn net.Conn) *Client {
	c := &Client{conn: conn}
	c.self = c
	return c
}

func (c *Client) Snapshot(ctx context.Context) (naspolicy.Config, error) {
	return c.call(ctx, 1, 0, naspolicy.Config{})
}

func (c *Client) Commit(ctx context.Context, expected uint64, next naspolicy.Config) error {
	_, err := c.call(ctx, 2, expected, next)
	return err
}

func (c *Client) Close() error {
	if c == nil || c.self != c {
		return naspolicystore.ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}

func (c *Client) call(ctx context.Context, action byte, expected uint64, next naspolicy.Config) (naspolicy.Config, error) {
	var zero naspolicy.Config
	if c == nil || c.self != c || ctx == nil {
		return zero, naspolicystore.ErrInvalid
	}
	if !c.mu.TryLock() {
		return zero, naspolicystore.ErrBusy
	}
	defer c.mu.Unlock()
	if c.closed {
		return zero, naspolicystore.ErrClosed
	}
	if c.review {
		return zero, naspolicystore.ErrReview
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	var payload []byte
	if action == 2 {
		if expected == 0 || expected == ^uint64(0) || next.Revision != expected+1 || next.Validate() != nil {
			return zero, naspolicystore.ErrInvalid
		}
		var err error
		payload, err = json.Marshal(next)
		if err != nil || len(payload) > naspolicy.MaxInputBytes {
			return zero, naspolicystore.ErrInvalid
		}
	}
	op, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	deadline, _ := op.Deadline()
	if c.conn.SetDeadline(deadline) != nil {
		c.review = true
		return zero, naspolicystore.ErrReview
	}
	joined := interrupt(op, c.conn)
	defer joined()
	fail := func() (naspolicy.Config, error) { c.review = true; return zero, naspolicystore.ErrReview }
	if writeFrame(c.conn, message(action, expected, payload)) != nil {
		return fail()
	}
	reply, err := readFrame(c.conn)
	if err != nil || op.Err() != nil || len(reply) < 10 || reply[0] != 1 || int(reply[1]) >= len(statuses) {
		return fail()
	}
	r := binary.BigEndian.Uint64(reply[2:10])
	if reply[1] != 0 {
		if r != 0 || len(reply) != 10 {
			return fail()
		}
		if reply[1] >= 4 {
			c.review = true
		}
		return zero, statuses[reply[1]]
	}
	if action == 2 {
		if r != next.Revision || len(reply) != 10 {
			return fail()
		}
		return zero, nil
	}
	got, err := naspolicy.Decode(bytes.NewReader(reply[10:]))
	if err != nil || got.Revision != r {
		return fail()
	}
	return got, nil
}
