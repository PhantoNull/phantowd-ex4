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
5. Select/qualify explicit administrator-authorized reconciliation and retention
   before writable admission. Closing an observer and reopening a path is not
   authority handoff. The first-release unclean-restart policy remains an open
   product decision, not a default selected by these diagnostics.
6. Qualify migration, actual EX4 storage placement, NAND/ECC, thermal safety,
   signed updates and demonstrated recovery before any physical installation.

No row or combination of diagnostic rows grants service activation. This map
does not freeze the experimental formats as a public firmware compatibility
contract or authorize operations on existing user disks.
