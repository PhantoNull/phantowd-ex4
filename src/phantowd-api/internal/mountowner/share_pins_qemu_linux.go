//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"os"
	"runtime"
)

type ServiceSharePinsQEMU = ServiceSharePins
type ServiceShareDescriptorQEMU = ServiceShareDescriptor

// RetainShareRootsQEMU additionally restricts its fixture caller to an ARM
// Versatile guest. Share descriptor admission uses the normal Linux path.
func (h *ServiceHandoff) RetainShareRootsQEMU() (*ServiceSharePins, error) {
	if h == nil || runtime.GOARCH != "arm" || os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, ErrHandoffInvalid
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" {
		return nil, ErrHandoffInvalid
	}
	return h.RetainShareRoots()
}
