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

The project-wide license and contributor policy remain an explicit open
decision. Do not assume that an unlicensed repository permits redistribution.
