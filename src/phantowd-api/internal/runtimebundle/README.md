<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Internal code-only runtime bundle inspection

`runtimebundle` is a read-only prerequisite for M4.4 root construction, not a
builder, approved runtime manifest or execution/installation token. Ordinary
product startup does not call it. It has no HTTP/RPC or JSON input/output.

`NewPlan` privately copies a fixed in-process file/alias roster supplied by a
future trusted build/release owner. It limits the plan to 256 regular files,
1024 bindings, 4096 total nodes, 16 path components and 64 MiB. Files have exact
SHA-256, size and mode 0444 or 0555. Aliases point directly to a declared file;
chains, collisions, ancestor conflicts and noncanonical paths are refused.
It does not infer trust by hashing the tree it is inspecting.

Linux `Inspect` independently duplicates an `O_PATH` root. The complete
code-only tree must be root:root on one kernel-enforced read-only mount, with
unique mount-ID support. It refuses the original `/`, undeclared entries,
remote/FUSE or other unqualified backing types (the fixed code-only roster is
tmpfs, SquashFS and ext-family),
special files, symlink traversal and crossing mounts. Directory traversal and
regular reads use descriptor-relative `openat2` with no weaker fallback.
Only declared aliases are read as text; their exact absolute in-root target
must match the fixed plan. Regular files require exact permissions, single
links, no file capabilities, bounded hash reads and stable metadata. Any error
returns no partial observation. Non-Linux inspection is unavailable.

The result contains internal counts only, cannot be serialized and holds no
descriptors or leases after return. This is a point-in-time check: privileged
writers through another mount, concurrent configuration updates, active root
replacement and later drift require separate owner serialization, retained
pins and revalidation. A read-only bind does not make other views immutable.
Trusted signature/model binding, ARM ABI and loader qualification, NSS/config,
state/grants/device rules, privilege profiles, construction/activation/recovery
and product wiring remain separate. No user data is read or modified here.
Context cancellation is checked between bounded local reads, not a guarantee
that an arbitrary kernel I/O stall can be interrupted.

The QEMU-only `cmd/qemu-runtime-bundle` checks the actual prepared Samba code
tree before fixture configuration/state/share grants are added. A fixed native
test helper creates a private read-only bind, drops every bounding capability
and switches to UID1801 with zero effective/permitted capabilities before the
probe. It never changes the parent mount namespace. The probe checks the real
roster and refuses five altered plans: digest, mode, alias target, omitted
daemon and symlink retyped as file. Cancellation must return no observation.
This fixture manifest is research evidence, not a signed product manifest.

The generic service launcher and Samba's bounded root profile are unchanged.
Neither this test helper nor probe is installed by a firmware package. Use the
existing [focused Samba wrapper](../../../../support/test-samba-root.ps1);
it reuses read-only cache/base inputs and bounded temporary space, without new
images or persistent volumes. Host tests cover plan copying/budgets/hierarchy,
serialization refusal, writable-root refusal and safe Linux open flags.
