//go:build !qemu || !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
)

func runQEMUSMBTest() error { return errors.New("SMB integration fixture requires Linux ARMv5 QEMU") }

func runQEMUIdentityClient(string) error {
	return errors.New("identity client fixture requires Linux ARMv5 QEMU")
}

func runQEMUMountGuardTest() error {
	return errors.New("mount guard fixture requires Linux ARMv5 QEMU")
}

func runQEMUMDStackTest() error {
	return errors.New("MD stack fixture requires Linux ARMv5 QEMU")
}

func runQEMUMDV10Fixture() error {
	return errors.New("MD v1.0 fixture requires Linux ARMv5 QEMU")
}

func runQEMUMDV10M34Fixture() error {
	return errors.New("MD v1.0/M3.4 fixture requires Linux ARMv5 QEMU")
}

func runQEMUMDV10BrokerClient() error {
	return errors.New("MD v1.0 broker client fixture requires Linux ARMv5 QEMU")
}

func observeTrustedMDV10ForBroker(_ context.Context) (storageMDV10ObservationSummary, error) {
	return storageMDV10ObservationSummary{}, errStorageBrokerUnavailable
}
