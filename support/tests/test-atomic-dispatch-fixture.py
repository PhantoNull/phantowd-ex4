# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location(
    "fixture", pathlib.Path(__file__).with_name("atomic_dispatch_fixture.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def evidence():
    symbols = []
    log = ["PHANTOWD_ATOMIC_ENV uid=1000 caps=0 nnp=1 helper_version=5"]
    index = 1
    for width in (1, 2, 4, 8):
        for operation in fixture.OPERATIONS:
            name = f"__atomic_{operation}_{width}"
            symbols.append(f" {index}: {index * 16:08x} 56 IFUNC GLOBAL "
                           "DEFAULT"
                           f" 12 {name}@@LIBATOMIC_1.0")
            log.append(f"PHANTOWD_ATOMIC_SYMBOL name={name} "
                       f"offset={index * 16 + 4:x}")
            index += 1
        log.append(f"PHANTOWD_ATOMIC_WIDTH bytes={width} "
                   "scenarios=50 increments=4000 guards=unchanged")
    log.extend([
        "PHANTOWD_ATOMIC_READY scope=arm926-qemu-only widths=4 symbols=36",
        "PHANTOWD_ATOMIC_NEGATIVE missing-symbol=refused",
        "PHANTOWD_ATOMIC_DONE"])
    return "\n".join(symbols).encode(), "\n".join(log).encode()


class CompareTests(unittest.TestCase):
    def test_complete(self):
        symbols, log = evidence()
        fixture.compare(symbols, log, 4096)
        fixture.compare(symbols, log.replace(b"\n", b"\r\n"), 4096)
        newer = log.replace(b"helper_version=5", b"helper_version=10")
        fixture.compare(symbols, newer, 4096)

    def test_refusals(self):
        symbols, log = evidence()
        cases = [
            (symbols, log.replace(b"caps=0", b"caps=1"), 4096),
            (symbols, log.replace(b"helper_version=5", b"helper_version=4"),
             4096),
            (symbols, log.replace(b"offset=14", b"offset=10", 1), 4096),
            (symbols, log.replace(b"offset=14", b"offset=1000", 1), 4096),
            (symbols, log.replace(b"offset=14", b"offset=0", 1), 4096),
            (symbols, log.replace(b"increments=4000", b"increments=3999"),
             4096),
            (symbols, log.replace(b"guards=unchanged", b"guards=changed"),
             4096),
            (symbols, log.replace(b"PHANTOWD_ATOMIC_DONE", b""), 4096),
            (symbols, log + b"\nPHANTOWD_ATOMIC_FAILED", 4096),
            (symbols, log + b"\nPHANTOWD_ATOMIC_DONE", 4096),
            (symbols, log.replace(b"fetch_sub_1", b"fetch_add_1"), 4096),
            (symbols.replace(b"fetch_sub_1", b"fetch_add_1"), log, 4096),
            (symbols.replace(b"IFUNC", b"FUNC", 1), log, 4096),
            (symbols.replace(b"@@LIBATOMIC_1.0", b"@@LIBATOMIC_2.0", 1),
             log, 4096),
            (symbols, log, 0),
            (symbols, log, 4 * 1024 * 1024 + 1),
            (symbols, log + b"x" * fixture.MAX_BYTES, 4096),
            (symbols + b"x" * fixture.MAX_BYTES, log, 4096),
            (symbols, log + b"\xff", 4096),
        ]
        for case in cases:
            with self.subTest(case=cases.index(case)):
                with self.assertRaises((ValueError, UnicodeError)):
                    fixture.compare(*case)

    def test_disposable_execution_contract(self):
        root = pathlib.Path(__file__).resolve().parents[2]
        runner_path = root / "support/tests/test-qemu-atomic-dispatch.sh"
        runner = runner_path.read_text()
        wrapper = (root / "support/test-atomic-dispatch.ps1").read_text()
        builder = (root / "support/container/build-qemu.sh").read_text()
        probe = (root / "support/tests/atomic-dispatch-fixture.c").read_text()
        for required in (
                'format=raw,if=scsi,snapshot=on', 'rootwait ro panic=-1',
                '-cpu arm926', '-nic none',
                'timeout --signal=TERM --kill-after=5 90',
                'PHANTOWD_ATOMIC_BASE_UNCHANGED', 'rm -rf "$scratch"',
                'export TMPDIR="$scratch"',
                'cp "$base/rootfs.ext2" "$scratch/rootfs.ext2"'):
            self.assertIn(required, runner)
        self.assertEqual(runner.count('qemu-system-arm \\\n'), 1)
        self.assertNotIn('-w -R', runner.split('cp "$base/rootfs.ext2"')[0])
        for required in (
                '--rm --pull never --network none --read-only '
                '--user 1000:1000',
                '--cap-drop ALL --security-opt no-new-privileges',
                '--cpus 2 --memory 1g --pids-limit 128',
                '--tmpfs /tmp:rw,exec,nosuid,nodev,size=256m',
                'readonly,volume-nocopy'):
            self.assertIn(required, wrapper)
        for forbidden in ('--privileged', '--device ', 'docker volume create',
                          'docker build ', 'docker pull '):
            self.assertNotIn(forbidden, wrapper)
        self.assertIn('support/tests/test-qemu-atomic-dispatch.sh', builder)
        self.assertIn('qemu-atomic-dispatch-failure.log', builder)
        self.assertIn('dlvsym(library, name, "LIBATOMIC_1.0")', probe)
        self.assertIn('drop_privileges();', probe)
        self.assertLess(probe.index('drop_privileges();'),
                        probe.index('library = dlopen('))


if __name__ == "__main__":
    unittest.main()
