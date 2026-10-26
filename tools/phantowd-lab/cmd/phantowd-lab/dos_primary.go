// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"github.com/PhantoNull/phantowd-ex4/phantowd-lab/diskimage"
	"io"
)

func inspectDOSPrimaryImage(args []string, output io.Writer) (int, error) {
	if len(args) != 1 {
		return 1, errors.New("usage: phantowd-lab inspect-dos-primary-image FILE")
	}
	file, size, err := openRegular(args[0])
	if err != nil {
		return 1, err
	}
	defer file.Close()
	report, err := diskimage.InspectDOSPrimary(file, size)
	if err != nil {
		return 1, err
	}
	if err := writeJSON(output, report); err != nil {
		return 1, err
	}
	if report.Status != diskimage.StatusDOSPrimary {
		return 2, nil
	}
	return 0, nil
}
