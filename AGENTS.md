# Agent instructions

This repository contains safety-critical embedded-NAS research. Keep public
content model-specific, reproducible and useful to contributors; exclude
operator-specific networks, workloads, hostnames, addresses and deployment
automation.

Before making changes:

1. Read `README.md`.
2. If the private `doc/` directory exists, read `doc/LLM-WIKI.md` and
   `doc/index.md`, then follow the relevant links.
3. Treat raw files under `doc/sources/` as immutable evidence.

For every durable discovery or decision, update the nearest canonical wiki
page, `doc/index.md`, and append a dated entry to `doc/log.md`. Run both normal
and strict checks with the `maintain-llm-wiki` checker before handing off.

Never commit credentials, private keys, tokens, serial numbers that are not
needed for hardware identification, proprietary firmware, raw flash dumps, or
user-specific runtime documentation. `doc/` is deliberately ignored because
it contains private LAN details.

Never produce or execute a flash-write command until the image format,
checksums, NAND geometry, ECC/OOB scheme, bad-block policy, boot validation,
and a tested recovery path are documented and independently reviewed.

Keep board/model output separate. Generated updates must be cryptographically
bound to an exact compatible hardware model.
