//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "context"

func runStorageBroker() error {
	return errStorageBrokerUnavailable
}

func collectStorageFromBroker() (storageSnapshot, error) {
	return storageSnapshot{}, errStorageBrokerUnavailable
}

func observeGPTPartitionIdentityFromBroker(context.Context) (storageGPTObservationSummary, error) {
	return storageGPTObservationSummary{}, errStorageBrokerUnavailable
}

func observeMDV10FromBroker(context.Context) (storageMDV10ObservationSummary, error) {
	return storageMDV10ObservationSummary{}, errStorageBrokerUnavailable
}

func verifyQEMUStorageBrokerFixture() error {
	return errStorageBrokerUnavailable
}
