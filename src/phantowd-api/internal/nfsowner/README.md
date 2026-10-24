# Experimental NFS lifetime (QEMU only)

Captures one typed candidate and fixed trusted memory backend without I/O.
Close serializes input/stopped checks before release; uncertainty retains review
without retry. Copied/absent handles refuse. Observe is historical, not health.
The five-second deadline is cooperative: a backend must honor its context.
Host tests cover closure/refusals/cancellation/exclusion; ARM checks memory-only
closure. A memory-only Start/Stop/Close lifecycle additionally verifies disabled
policy, partial-start settlement, cancellation and stop-before-release. Accepted
stop uses an independent five-second context; uncertainty retains review without
restart. Check serializes fresh input/probe/input observations for running or
disabled memory lifetimes. Failure retains review; only a running lifetime
attempts one independent stop. Restoration cannot retry cleanup or release.
The guest checks healthy and input-loss lifetimes; the smoke driver requires one
exact receipt. These sequential observations are not continuous health.
No kernel backend, polling supervisor, HTTP or product activation exists.

Linux/QEMU ExportRootsQEMU separately captures original-lease directory metadata
and retains uncertain construction/closure. Native refusal/privacy/model tests
and a guarded ARM fixture cover mixed roots, whole-volume capture, missing and
symlink refusal, parent-close exclusion and replacement/restoration review.
Known disposal after path drift is not uncertain-close recovery; real close
failure injection and the complete fault matrix remain unqualified. No descriptor
getter, data access or service join is supplied.
