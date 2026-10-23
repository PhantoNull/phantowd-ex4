# Experimental NFS lifetime (QEMU only)

Captures one typed candidate and fixed trusted memory backend without I/O.
Close serializes input/stopped checks before release; uncertainty retains review
without retry. Copied/absent handles refuse. Observe is historical, not health.
The five-second deadline is cooperative: a backend must honor its context.
Host tests cover closure/refusals/cancellation/exclusion; ARM checks memory-only
closure. A memory-only Start/Stop/Close lifecycle additionally verifies disabled
policy, partial-start settlement, cancellation and stop-before-release. Accepted
stop uses an independent five-second context; uncertainty retains review without
restart. No fresh health check, kernel backend, HTTP or product activation exists.
