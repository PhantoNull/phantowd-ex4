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

The compile-only Stage B3 workflow runs for relevant pushes to non-`main`
branches and when a pull request with relevant changes is opened or reopened.
GitHub compares only the pushed commit range for `push` path filters, while
`pull_request` path filters consider the PR's three-dot diff. Later pushes are
therefore filtered by the files changed in that push, so a docs-only update to
a firmware PR does not repeat the long build. Opening a PR after a relevant
branch push can run the check once more against the proposed merge. See
[GitHub's path-filter documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#onpushpull_requestpull_request_targetpaths).
The earlier Stage B and B2 candidates remain manually dispatched; they are
not rebuilt for each B3 change. The QEMU baseline uses the same trigger policy
for QEMU, package, API, and build-input changes. Both workflows can also be
dispatched manually. Neither successful CI nor a green PR check authorizes a
physical boot or flash operation.

Unless a contribution clearly derives from an upstream work under another
compatible license, contributions are accepted under Apache-2.0. Linux kernel
and device-tree derivatives must remain GPL-2.0-only. Add or preserve SPDX
metadata and update `REUSE.toml` when introducing a new path not already
covered there. See `LICENSE-POLICY.md` for the complete repository policy.
