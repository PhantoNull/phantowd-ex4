//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/networkinventory"
)

func exerciseQEMUNetworkInventory() error {
	if networkinventory.QEMUObjectFixture() != nil {
		return errors.New("generated nexthop observation failed")
	}
	o, err := networkinventory.Collect(context.Background())
	if err != nil {
		return errors.New("kernel network observation failed")
	}
	summary, err := o.Summary()
	if err != nil || summary.Interfaces < 1 || summary.Addresses < 1 || summary.Routes < 1 || summary.Rules < 1 || summary.UnresolvedRoutes > summary.Routes || summary.UnresolvedRules > summary.Rules || summary.UnresolvedNextHopObjects > summary.NextHopObjects || networkinventory.Recheck(context.Background(), o) != nil {
		return errors.New("kernel network observation incomplete or changed")
	}
	if _, err := json.Marshal(o); err == nil {
		return errors.New("private network observation serialized")
	}
	copy := *o
	for _, invalid := range []*networkinventory.Observation{nil, {}, &copy} {
		if _, err := invalid.Summary(); err != networkinventory.ErrUnavailable {
			return errors.New("forged network observation accepted")
		}
		if err := networkinventory.Recheck(context.Background(), invalid); err != networkinventory.ErrUnavailable {
			return errors.New("forged network recheck accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := networkinventory.Collect(ctx); got != nil || err != networkinventory.ErrUnavailable {
		return errors.New("network cancellation ignored")
	}
	return nil
}
