<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# State ownership and bootstrap composition

This is the current code ownership map, not an installable layout or permission
to open product writers. Physical EX4 placement, complete product namespace,
provisioning, retention, reconciliation and recovery remain unqualified. Paths
below are names within each owner's dedicated role, not NAS deployment paths.

## Current roles

Normal non-root API serving validates its transport and incompatible development
policy-store options before opening the account or policy stores. TLS validation
may read the explicitly supplied certificate/key files; this is not an I/O-free
bootstrap probe. State-directory option presence and the root-serving refusal
remain earlier checks. This ordering prevents known-invalid options from entering
state constructors; it does not qualify complete state classification, product
provisioning, all later startup failures, rollback or recovery.

| Role | Existing state / sole mutator | Observation and composition requirement |
| --- | --- | --- |
| Panel administrator | `accounts.json` / `.accounts.pending`; [admincredentials.Store](src/phantowd-api/admincredentials/store_linux.go), then the authorized account controller | `Store.Open` establishes a sync boundary: not a read-only bootstrap probe. The explicit protected reader returns only missing/valid document metadata and revision. Canonical setup-only v1 reads as revision1 without rewriting; this is not WD credential import, authentication or enrollment permission. |
| Desired SMB/NFS/iSCSI policy | [NAS policy](src/phantowd-api/internal/naspolicy) plus per-operation bundles and session declarations; the [history writer](src/phantowd-api/internal/policytransaction/README.md) remains fresh-state/QEMU-only | The [session/history observer](src/phantowd-api/internal/policyevidencefs/README.md) holds the actual policy/operation/session locks and compares the exact independently trusted opening checkpoint. No matching kind proves historical successful returns, browser delivery, clean shutdown or service permission. |
| Managed Unix identities | `registry/service-accounts.json` and `operations/<account-id>/identity-operation.json`, with their fixed pending names; [identityowner.Owner](src/phantowd-api/identityowner/README.md) coordinates the ledger, native journals and external Unix executor | Store opening has sync effects; Owner startup can recover interrupted Samba intents to review. Do not construct an Owner merely to classify existing state. Its non-recovering lookup is read-only **within an already admitted Owner**, not a non-mutating bootstrap constructor. The separate experimental retained namespace reader performs no recovery; complete product startup/resource/fault qualification remains required. |
| Managed Samba enrollment | Per-account `smb/smb-operation.json` / `.smb-operation.pending`, [smbprovision](src/phantowd-api/internal/smbprovision/README.md), plus real Samba private state | IdentityOwner and its captured backend remain sole enrollment/disable/enable mutators. Stable journal data alone does not prove passdb, active-session or runtime readiness. Product startup/recovery and producer completeness remain unqualified; status-producer work is deferred. |
| Volume registry | `volumes.json`; [volumeregistry.Reader](src/phantowd-api/internal/volumeregistry/README.md) reads explicitly provisioned claims | No product registration writer is implemented. Preserve explicit logical VolumeIDs and reader-bound fresh observations; valid registry bytes alone do not establish unique devices, mounted authority, MD/import eligibility or absence of consumers. |
| iSCSI CHAP material | `chap-secrets.json` / `.chap-secrets.pending`; [iscsicredentials.Owner](src/phantowd-api/internal/iscsicredentials/README.md) retains material for a fixed consumer, not provisioning/rotation | Owner.Open establishes a sync boundary. The explicit root-only diagnostic reader validates the existing document but returns no material or SecretRefs. Valid metadata does not prove entropy, every policy reference, retained consumer ownership or target readiness. Local storage is root-only plaintext, not encrypted at rest. |
| Installation / checkpoint / session succession | Experimental declarations currently capture constructor-supplied installation and sequence; [session contract](src/phantowd-api/internal/policyepochjournal/README.md) | No product installation identity/provisioning/successor allocator or rollback resistance is implemented. A random ID or self-consistent digest cannot create that provenance. Do not derive a trusted checkpoint from the same history being checked. |
| Network and system settings | Desired models and proposal diagnostics; [roadmap M6](ROADMAP.md#m6-network-and-system-services) | Qualified persistent role ownership/publication, live trial/confirmation/rollback, time and administration integration remain required. Do not invent filenames or classify an unimplemented role as optional/ready. |
| TLS identity and trust | Development/fixture HTTPS exists; [roadmap M5](ROADMAP.md#m5-product-web-management-and-security) | Product private-key ownership, issuance/renewal, trust, backup/recovery and retained listener composition remain required. A development certificate is not a provisioned appliance identity. |

## Retained desired-policy candidate observations

The separate internal `BuildFromLeasedNASOwners` adapter can derive file-service
candidates from an already admitted NAS policy lease, retained identity lease
and mounted roster, bracketing the existing storage → identity calculation with
checks of the same policy claim. It opens/recovers no writer and acquires/releases
no lease. Its output is data, not a new role owner, history-backed boot admission,
atomic appliance generation or permission to activate services. The disposable
policy Owner used by its ARM test does not select product state placement or
replace the history writer/coordinator requirements above.

## Read-only credential observations

The fixed `OpenAdministratorCredentials` / `OpenCHAPCredentials` constructors
reuse the protected read-only namespace engine. They capture one dedicated
original directory/actual flock, fixed names/decoder, original file, unique mount
and path identity, complete census and file/directory watches. CHAP opening is
root-only; HTTP code receives no credential value or caller-selected codec.

`ObserveCredentials` returns private kind/revision metadata only. Missing is not
pristine or setup permission. Pending suppresses **all** content reads; malformed
or changed state and I/O/cancellation uncertainty retain review. Restored files
or another context cannot resume it. No constructor creates, syncs, resets,
promotes, enrolls, authenticates, consumes secrets or starts services. The normal
credential writers and authentication/session behavior are unchanged.

These readers are separate diagnostic lifetimes, not continuous ownership from
the previous writer or a ready-made whole-appliance bootstrap coordinator.
Complete constructor/temporary-close/watch/larger fault and physical-medium
qualification is still required. See [implementation status](IMPLEMENTATION-STATUS.md)
for the exact tested scope rather than inferring it from this design map.

## Required composition

The private [identity-document comparison](src/phantowd-api/internal/identityevidence/README.md)
checks complete supplied registry/native/enrollment document links without
constructing IdentityOwner or invoking recovery/runtime backends. Its fixed
no-action diagnosis is not a retained namespace census, live identity/passdb
observation or whole-appliance startup decision. A separate explicit
`OpenIdentity`/`ObserveIdentity` profile now retains the actual root/registry/
operations/account/optional-enrollment locks, fixed bounded census, original
files/mounts/watches and pending-before-read refusal. This diagnostic is not
continuous writer ownership, live Unix/passdb readiness or admission; complete
fault/resource/role/consumer/startup composition remains open.

1. Define and provision the complete required role set under independently
   trusted installation/medium identity; missing or unimplemented roles must
   never silently become pristine, optional or ready.
2. Retain original root and actual role locks in one documented order while
   classifying all roles, their journals and cross-role references. Individually
   valid revisions need not form one consistent appliance generation.
3. Account for every existing identity, mount, share/target process, backing and
   credential consumer. A matching policy declaration cannot replace settlement.
4. Preserve uncertain evidence and the containing review decision. Never call
   writer Open, fsync, pending deletion or startup recovery to manufacture a
   successful read-only observation or erase a previous error.
5. Implement and qualify automatic recovery/restart for the first release as
   specified below. Closing an observer and reopening a path is not authority
   handoff. Unresolved evidence still cannot grant writable admission.
6. Qualify migration, actual EX4 storage placement, NAND/ECC, thermal safety,
   signed updates and demonstrated recovery before any physical installation.

No row or combination of diagnostic rows grants service activation. This map
does not freeze the experimental formats as a public firmware compatibility
contract or authorize operations on existing user disks.

## First-release automatic recovery requirement

The selected product behavior is automatic recovery and restart of desired-enabled
SMB/NFS/iSCSI services after an ordinary unclean shutdown, without a mandatory
administrator confirmation on every boot. This is a required release capability,
not implemented behavior or permission to change the existing diagnostic/Owner
contracts. A manual-only initial release does not satisfy this requirement.

The future product boot coordinator must:

1. Validate the installation/state medium and complete role set under original
   locks before opening writers. Missing/corrupt/foreign state is not first boot.
   Establish a new qualified boot lifetime; never reuse stale process identities,
   mount handles, runtime claims or a prior boot's service-ready observation.
2. Compare exact confirmed policy, operation/session history, native identities,
   enrollment and protected credential references. Recover only explicitly
   specified, tested interrupted states, preserving original evidence and
   recording durable recovery progress. Byte equality or a missing reply alone
   cannot authorize retry, promotion, pending-file deletion or secret recreation.
3. Reacquire qualified stable-volume, supported array/filesystem, runtime-code,
   network and credential authority. Recheck identity, permissions, retained
   mount/backing handles and whole-use exclusion before any service starts.
   Never substitute an empty local mountpoint or infer identity from a bay/path.
4. Start each desired-enabled service at most once for that admitted boot
   transition, after its dependencies and policy revision agree. Desired-disabled
   services remain disabled. Publish running only after actual readiness/access
   checks, not process creation. Ordinary unclean shutdown alone must not force
   manual confirmation or silently disable otherwise recoverable services.
5. On ambiguity, incompatible storage, failed recovery or uncertain effects,
   withhold affected service admission and expose a persistent, redacted recovery
   diagnosis/notification with an explicit remediation path. Independently safe
   services may continue only when shared-state/consumer isolation is proven.
   Never reset a reviewed Owner, blind-replay a mutation or enter a restart loop.

Existing in-lifetime drift/uncertain-stop contracts remain terminal review with
retained authority: a boot recovery coordinator is a separate, qualified protocol,
not permission to call Open again until a failure disappears. Manual recovery is
an exceptional response to unresolved faults, not the default after every outage.

Before integration, specify the complete state/transition and action matrix,
durable checkpoints, allowed recovery mutations, lock order, interruption/space
bounds and consumer handoff. First prove normal and interrupted reboots using
disposable host/QEMU storage, real service access and verified process cleanup.
Require confirmed old/new state, disabled-service preservation, no fallback writes,
no ambiguous-disk admission, and no startup after failed/uncertain recovery.
Actual power-loss durability, physical EX4 placement, cooling and demonstrated
recovery remain separate hardware/release gates. No NAS operation is authorized.

## Required boot/recovery acceptance matrix

This is the minimum product acceptance matrix, not an implemented coordinator,
complete per-role recovery algorithm or permission to reinterpret a diagnostic
match as admission. All rows require independently trusted installation/medium
identity and the complete role census under original locks. Missing prerequisites
cannot be supplied by a digest, previous boot receipt or caller-selected backend.

| Observed boot state | Required product outcome | Required evidence before integration |
| --- | --- | --- |
| Confirmed coherent state after a normal shutdown; service desired-enabled | Reconstruct fresh dependencies and start automatically, once for the admitted transition; publish running only after readiness | Different kernel boot IDs; actual SMB/NFS/iSCSI access from retained policy/data, original identities and verified cleanup; no panel enable action |
| Same confirmed coherent state after an ordinary unclean shutdown, with an open prior session but no unresolved operation | Execute the explicitly qualified recovery transition and start automatically; missing clean closure alone must not force routine manual confirmation | Loss after stable publication and during ordinary service use, then a new kernel; preserved original state/data and real service access; do not relabel the previous session clean or invent old successful syscall returns |
| Coherent state with a service desired-disabled | Preserve disabled state, regardless of an earlier boot's process/listener claims | Normal and unclean reboot controls with no service listener, process, target or backing consumer for that disabled service |
| Interrupted policy/identity/credential or recovery step covered by a specified recovery rule | Apply only that rule under original authority, preserving original evidence and recording new durable progress before dependent startup | Interruption at every rule's durable boundary; repeated interruption cannot allocate a replacement operation, erase the original evidence or duplicate effects; real old/new state and readiness checks |
| Pending, inconsistent, foreign, restored/cloned, incomplete or unsupported evidence without a qualified recovery rule | Withhold affected admission and expose a redacted diagnosis/remediation path; no implicit adoption, enrollment, promotion, rollback or retry | Missing/duplicate/unknown-role and history/checkpoint controls; no writer/backend/service effects from a matching partial diagnosis; unaffected services continue only with proven isolation |
| Stable-volume, array/filesystem, permissions, network, code or credential dependency is missing, changed or ambiguous | Keep the affected service unavailable instead of using another bay, empty directory, stale mount or credential | Clone/missing/reordered-disk, replaced mount/root, stale authority, invalid access and credential faults; unchanged data and no fallback writes |
| Recovery cannot establish its required durable boundary because of ENOSPC, read-only medium, I/O/cancellation or uncertain closure | Preserve existing evidence and the containing recovery fence; no running publication or authority release from an uncertain outcome | Injected returning and process-loss faults, including failure to persist an additional diagnostic; verify retained inputs and bounded cleanup, not a fabricated durable-success marker |

The current clean two-boot fixtures cover only selected normal-path prerequisites;
they do not satisfy the unclean/recovery rows. A new synchronization can establish
a new tested boundary, never prove the previous boot's lost return values.
Recovered services need fresh process, mount, identity, credential and runtime
authority; previous boot observations are historical evidence only. In-lifetime
review remains terminal under the existing Owner contracts, not permission to
close/reopen until a failure disappears. Installation/checkpoint provenance,
per-role allowed mutations, lock order, state-medium selection and interrupted
recovery handoff must still be specified and qualified before product startup.
