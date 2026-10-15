<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Management-plane threat model

Status: source-based draft, not independent security sign-off or authorization
to expose the development server. Reassess this document when a listener,
credential workflow, backend, privilege or persistent-state role changes.
The current firmware remains non-installable. See the [product roadmap](../../ROADMAP.md).

## System and protected assets

The development API embeds fixed static assets, authenticates one panel
administrator and exposes observations and desired SMB/NFS configuration.
Panel credentials are distinct from Unix/Samba identities and iSCSI CHAP.
There is no HTTP service-activation, RAID-mutation, installer or reset workflow.
An authenticated panel session is not storage, execution or installation authority.

Protect administrator verifiers, session/CSRF tokens and TLS keys; private
configuration and topology; user data and stable volume identity; privileged
service inputs and retained resources; update trust roots and per-unit identity;
and cooling/recovery availability. A policy revision or successful preview
does not prove a running service, compatible disk or recoverable appliance.

Consider unauthenticated direct clients, hostile web pages, compromised browser
code/extensions, local processes, malicious release/configuration input, and
an authenticated administrator requesting an unsafe operation. Origin headers
are browser-context checks, not proof of ownership: a non-browser client can
supply them. An attacker controlling root, the API's own Unix identity or the
boot chain can violate trusted filesystem/process prerequisites. Current code
does not establish secure boot or protection against those actors.

## Trust boundaries

| Boundary | Current source/control | Qualification still required |
| --- | --- | --- |
| Client → listener | [transport.go](transport.go) validates address, origin and supplied TLS material; default is loopback HTTP | Product interface admission, certificate trust/lifecycle, network rollback and listener policy |
| Request → panel identity | [auth_controller.go](auth_controller.go), [auth_session.go](auth_session.go), [auth_password.go](auth_password.go) | Owner-presence enrollment/reset; complete endpoint/header/parser review and browser tests |
| Panel → desired state | [service_state_http.go](service_state_http.go), [fileservicestore](fileservicestore/README.md) | Complete boot bundle, retained ownership, durable recovery and explicit reconciliation |
| API → storage/privileged owners | [volume probe](../phantowd-volume-probe/README.md), [revision owner](internal/revisionstore/README.md), identity/runtime owners | Complete production composition, global-use/session exclusion, qualified media and peripherals |
| GitHub/input → update authority | [release verification](../../tools/phantowd-lab/releaseverify/README.md), [GitHub reader](../../tools/phantowd-lab/githubrelease/README.md) | Provisioned keys/model identity, provenance, signed staging, target transaction and demonstrated recovery |

The transport loader supports explicitly configured TLS listeners outside
loopback; syntactic acceptance is not product/LAN admission. The development
file-service save adapter additionally requires a loopback listener and one
policy authority. Do not bypass those restrictions through a proxy.

## Current HTTP surface

This inventory describes handlers, not deployable product capabilities. Do not
assume one universal authorization wrapper: each specialized route owns checks.

| Route group | Methods and access | Effect / important limit |
| --- | --- | --- |
| `/`, fixed `/assets/*`, `/healthz` | Public GET; fixed asset paths and input/method checks | Health means process-only, not appliance readiness. [http.go](http.go) |
| `/api/v1/auth/status` | Public GET; no query/body | Reveals setup/authentication flags, not owner-presence evidence |
| `/api/v1/auth/setup`, `/api/v1/auth/login` | POST; configured Origin/Host/scheme and bounded JSON; setup only while account is absent | Development first-account creation/login. Origin does not authorize the first owner. [auth_controller.go](auth_controller.go) |
| `/api/v1/auth/session` | GET; configured account and current cookie | Returns private CSRF/expiry data; not service credentials |
| `/api/v1/auth/logout`, `/logout-all`, `/password` | POST; current session, Origin and CSRF; password also verifies current credentials | Panel-session revocation/credential transaction, not SMB/NFS client revocation |
| `/api/v1/system`, `/storage`, `/arrays`, `/mounts` | GET; configured account/session and no query/body | Read-only diagnostics; unlike stored-policy reads, this common branch does not apply `validOrigin` to GET |
| `/api/v1/shares/configuration` | GET; session, Host/scheme and Origin if supplied; one active read | Private desired policy only. [share_policy_http.go](share_policy_http.go) |
| `/api/v1/file-services/configuration`, `/backup`, `/restore-preview` | GET/PUT, GET, POST respectively; session and Host/scheme; writes/previews also require Origin/CSRF; one shared active operation | Explicit development store only; restore-preview does not save. No service activation. [service_state_http.go](service_state_http.go), [backup handlers](service_backup_http.go) |
| `/api/v1/file-services/preview` | POST; session, Origin/CSRF, typed bounded body; one active preview | Pure desired-policy validation/rendering. [file_service_http.go](file_service_http.go) |
| `/api/v1/storage/gpt-observation` | Explicit POST; session, Origin/CSRF and empty input; one active observation | Fixed broker read-only metadata operation, not caller-selected devices, import or mount. [storage_partition_http.go](storage_partition_http.go) |

The server's eight-request gate, header/body timeouts and operation-specific
caps are defensive bounds, not demonstrated denial-of-service resistance.
The GPT response has its own longer deadline; do not assume all jobs end at the
general five-second write timeout. Cancellation requests do not prove kernel
I/O or a service stopped. Current shutdown is not a verified appliance teardown.

## Threat register and acceptance packets

All open product gates below block general LAN deployment. A fixed code defect
does not close a whole threat class. Packet IDs are review/handoff labels, not
persistent formats or permissions.

| ID | Threat and existing evidence | Required next evidence / owner |
| --- | --- | --- |
| TM-01 | Plaintext external binding disguised by a loopback public origin. Configuration regression reproduced twice; guard now checks both independently configured hosts. IPv4/IPv6/wildcard/name refusals and valid loopback/HTTPS controls exist in [transport_test.go](transport_test.go). | Preserve zero usable configuration on refusal and test the actual startup path; full own-head integration and product interface policy remain M5.2/M6 gates |
| TM-02 | First-owner takeover/reset misuse. Current setup checks an absent account, not physical owner presence. TLS/Origin alone cannot establish who should enroll. | Specify authorized initial enrollment, bounded presence window, interrupted provisioning and data-preserving reset/recovery; M5.1/M1/M7 decision required before any enrollment listener |
| TM-03 | TLS downgrade, wrong name, expired certificate, key substitution or clock failure. Loader checks supplied pair/name/time and key permissions, bounds certificate/key PEM at256/64KiB and checks opened leaf metadata; Linux uses no-follow/nonblocking opens. TLS1.2 minimum, no certificate issuer/rotation workflow. | Retained key/parent handling, first-use trust and naming, renewal/replacement, stale clock, reload/restart, concurrent-change/low-level I/O faults and recovery tests; byte bounds do not provide an I/O deadline or total handshake-memory limit. M5.2/M6.4 |
| TM-04 | Session theft, replay and concurrent revocation. Random tokens/CSRF, hashed session lookup, eight-session/30-minute process-local limits and Strict/HttpOnly cookies exist; TLS uses Secure `__Host-` cookies. Epochs fence issuance across global revocation. | Uniform duplicate-cookie/header review, real-browser lifecycle tests, reboot/reset semantics and privilege model. [session tests](auth_session_test.go), [revocation tests](auth_revocation_test.go), [password tests](auth_password_test.go); M5.3 |
| TM-05 | Cross-origin requests, hostile JSON/HTML and resource exhaustion. Mutation handlers use Origin/Host/CSRF, typed limits and non-queuing gates; diagnostics use CSP/no-store and text-only UI rendering. Setup/login now reuse the exact-key/Unicode envelope, rejecting ambiguous credentials before operations; HTTP tests retain account/session state and valid Unicode. | Audit every parser, header and route rather than infer uniformity. Broader error redaction, browser response budgets, accessibility and realistic ARM memory/load tests remain M5.3/M5.5/M11 gates |
| TM-06 | Lost replies, reboot or full/RO state falsely reported as confirmed. Existing stores preserve uncertain outcomes; desired-state saves never mean services applied. Retained read-only bootstrap is not durable recovery. | Approved operation/bundle semantics, interruption at every durable boundary, explicit reconciliation with no automatic retry, complete-role startup admission and qualified state medium; M1.3/M1.2/M7 |
| TM-07 | A valid session or serialized observation becomes privileged execution/storage authority. Current handlers do not activate services; internal owners/claims and broker inputs are separate. | Fixed authenticated internal channel, complete retained identity/storage/code/network/state composition, stale/forged/copied input refusal, concurrent revocation and verified teardown before release; M2–M4/M9 |
| TM-08 | Unsafe authorized disk/LUN/RAID/network/update action or cross-protocol writer. Parsers/previews and lexical overlap warnings do not establish global exclusivity, compatibility or rollback. | Actual consumer/session inventory and safe jobs/reconciliation, qualified expendable media, recoverable network trials and thermally safe board support; M3/M4/M6–M10 |
| TM-09 | Forged/rollback release or secret-bearing diagnostics. Host tooling verifies signed exact-target metadata/payloads and redacts request/body errors; trust keys and installed versions remain caller declarations. | Product key/model provisioning, authorized rotation/rollback policy, source/staging provenance, power-loss transaction and independently demonstrated recovery; M10/M11 |
| TM-10 | Availability loss despite nominal limits: shared login quota, expensive KDF, blocked storage, hostile TLS clients, observer polling or unfinished shutdown. Argon2 work has one process-wide slot and bounded verifier parameters, but running KDF work is not interruptible. | Measured EX4 KDF/RSS/latency/thermal budgets, mixed-load and overload campaigns, foreground management availability, bounded retention and verified whole-service shutdown; M5/M7/M11 |

## Product admission checklist

- Owner-presence enrollment/reset and trust/certificate recovery are specified,
  implemented and independently reviewed; no default password or first-client-wins
  provisioning is advertised as secure initial use.
- Complete persistent roles are provisioned/observed under retained authority.
  Corrupt, partial, foreign, restored or unresolved state cannot silently become
  pristine or service-ready. A file hash/revision does not prove prior durability.
- Every enabled HTTP operation has exact authorization/admission, bounded input
  and work, tested concurrency/error/revocation semantics and redacted output.
  A permitted administrator request must still pass safety checks.
- Backend readiness comes from qualified owners, not a UI flag, client path,
  stored `enabled` bit, successful renderer or matching serialized diagnostics.
- Browser/native/ARM integration, hardware cooling/network/storage/recovery,
  dependency/legal/security review and release qualification carry exact source
  and environment evidence. QEMU cannot certify EX4 peripherals or power loss.
- A separate reviewer records remaining risks and explicit accept/reject decisions
  for the exact advertised deployment. This draft is not that sign-off.

## Review method and evidence

Use assets, actors, data flows, trust boundaries, concrete threats, mitigations
and repeatable acceptance evidence. This follows the decomposition and review
approach in the [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html),
not a certification or universal checklist. Origin/token checks are layered
browser-request defenses; they do not replace ownership or operation authorization.
See the [OWASP CSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

Start with the linked source/tests and [component contract](README.md), then
review the [recovery design](internal/revisionstore/RECOVERY-DESIGN.md) and
[roadmap](../../ROADMAP.md#m5-product-web-management-and-security). Record exact
commit, runtime, negative cases, limits and unresolved questions. Preserve old
failure evidence; passing controls do not close untested product gates.
