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

Unless a contribution clearly derives from an upstream work under another
compatible license, contributions are accepted under Apache-2.0. Linux kernel
and device-tree derivatives must remain GPL-2.0-only. Add or preserve SPDX
metadata and update `REUSE.toml` when introducing a new path not already
covered there. See `LICENSE-POLICY.md` for the complete repository policy.
