// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

// mdadm needs the operation mode before global options such as --config.
func qemuMDCreateArguments() []string {
	return []string{
		"--create", "--config=/dev/null", "/dev/md0", "--metadata=1.2", "--name=phantowd-qemu-test",
		"--level=raid1", "--raid-devices=2", "--assume-clean", "/dev/sde", "/dev/sdf",
	}
}

func qemuMDV10CreateArguments() []string {
	return []string{
		"--create", "--config=/dev/null", "/dev/md0", "--metadata=1.0", "--name=phantowd-qemu-v10-test",
		"--level=raid1", "--raid-devices=2", "--assume-clean", "/dev/sdb1", "/dev/sdc1",
	}
}

func qemuMDV10StopArguments() []string {
	return []string{"--stop", "--config=/dev/null", "/dev/md0"}
}

func qemuMDStopArguments() []string {
	return []string{"--stop", "--config=/dev/null", "/dev/md0"}
}
