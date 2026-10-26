# Local desired NAS policy server

The internal Linux Unix-stream server borrows an initialized NAS Owner for
strict snapshot/commit with revision/consumer fences, root construction and
configured kernel peer UID. Bounded frames share a five-second operation budget;
idle follows cancellation; Owner filesystem/lock cancellation is cooperative.
Host tests use real Unix streams/store; only root construction has a host seam.
Channel loss never retries or closes the parent. No service activation follows.
The retained client checks its root peer and refuses further I/O after uncertainty.
Fixed ARM children test authenticated loopback HTTPS busy/CAS/readback through
the retained client and original root Owner, with independent parent verification.
The handler captures snapshot/commit authority once and never opens or closes it.
Product listener, boot/router wiring and service activation remain open.
