# Contributing

The project is not ready for general device flashing. Contributions are most
useful when they improve reproducible, read-only hardware discovery, document
evidence, add tests, or make recovery safer.

- Do not upload vendor firmware or device dumps.
- Prefer scripts that operate on a user-supplied image and verify hashes before
  and after each transformation.
- Record the exact model, board revision, firmware version, and command output
  behind hardware claims.
- Keep support for each hardware model isolated in its own board definition.
- Preserve SPDX identifiers and upstream licensing notices.
- Do not include secrets, personal network details, or signing keys.

## CI scope

Pull requests that change the current EX4 hardware-probe inputs run the
compile-only Stage B3 workflow. The earlier Stage B and B2 candidates are
retained as manually dispatched checks; they are not rebuilt for each B3
change. The QEMU baseline runs automatically for QEMU, package, API, or its
build-input changes and can be dispatched manually for other cases. These
long builds do not repeat on every push to `main`; the pull-request result is
the gate for the merged change.

Unless a contribution clearly derives from an upstream work under another
compatible license, contributions are accepted under Apache-2.0. Linux kernel
and device-tree derivatives must remain GPL-2.0-only. Add or preserve SPDX
metadata and update `REUSE.toml` when introducing a new path not already
covered there. See `LICENSE-POLICY.md` for the complete repository policy.
