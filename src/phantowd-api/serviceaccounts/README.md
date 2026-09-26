# Native file-service identity registry

This package reserves stable native account identities separately from panel
administrators, share grants and Samba credentials. It does not edit Unix files,
provision passdb, change ownership, enable a service or expose an API endpoint.

The strict version-1 JSON document contains an explicit allocation range,
revision and account records (project ID, name, UID, private primary GID and
desired state). It contains no credential, password hash or shell/home settings.
Every new account starts disabled. Names, project IDs and numeric identities
are permanent reservations, including retired records. Rename, UID/GID changes,
record removal and resurrection are deliberately absent. Enabling/disabling is
desired state, not evidence that Samba sessions or other protocols changed.

The separate [local identity observer](../unixidentity/README.md) can derive
exclusions and assess exact/partial/conflicting identities from supplied Unix
files. It does not establish complete NSS discovery, project ownership or a
transaction-safe permission to provision/adopt those accounts.

Native ranges must be explicitly selected inside 1000..60000; no default is
selected by this library. Allocation chooses the first number unused in both
UID and GID namespaces and assigns a same-number private primary group. Caller
exclusions are mandatory, bounded and may include system identities and imported
data ownership. They are not a live-discovery guarantee. The eventual privileged
owner must validate their completeness/freshness under its operation lock and
recheck external identity before provisioning. No existing WD UID/GID is silently
renumbered or adopted: legacy shared groups and imports require a distinct,
verified compatibility/migration path. Unknown or offline data ownership remains
an allocation qualification gap, not permission to reuse an ID.

There are at most 128 non-retired accounts and 1024 lifetime records. Exhaustion
fails explicitly, never erases history. The input limit is 256 KiB; duplicate,
unknown, missing or null fields, invalid Unicode, excess nesting, inconsistent
identities and trailing JSON are refused. Errors omit caller values. Numeric
fields and revisions are bounded; revision overflow is refused.

`BindShares` matches granted user references by **both** ID and exact name and
requires enabled desired state. It returns sorted, independent bindings and both
input revisions. Missing/mismatched/disabled/retired references fail the whole
binding; unused references do not grant access. These are not live Unix/Samba
identity checks, permission checks or activation authorization. Policy and
registry writes are not a cross-store transaction; activation must revalidate
both revisions together with actual runtime state.

The Linux `serviceaccountstore` adapter uses the existing private-directory,
exclusive-lock, fsync/rename revision engine with fixed `service-accounts.json`
and `.service-accounts.pending` names. Only initialization and typed create/state
operations are exposed: an arbitrary document replacement could erase retired
identities, so there is no raw Commit method. It serializes load/plan/commit and
uses expected revisions; stale writers fail. Initialization creates only an
empty ledger, refuses existing state and never provisions a directory. Retired
identities survive close/reopen; pending/corrupt state is never auto-promoted or
reset. This file is separate from `accounts.json` administrator credentials.
Generic storage errors retain the revisionstore sentinels; planning errors use
the serviceaccounts sentinels. An uncertain commit requires close/reopen and
reconciliation, not a blind retry.

Tests use synthetic identities and private temporary directories. The guarded
two-boot ARMv5 fixture also retains a real Unix identity and private Samba passdb:
it verifies the ledger/UID/GID, disabled state and rotated password after reboot,
then explicitly enables fresh-client access without recreating credentials.
This is a fixed test scenario, not a provisioning/reconciliation implementation;
see the [credential lifecycle contract](../README.md#smb-credential-lifecycle-boundary).

Production
state provisioning, anti-rollback/recovery, full power-loss qualification,
passdb lifecycle, qualified live-identity reconciliation, privileged ownership/transport, active
session revocation, UI integration and legacy migration remain unimplemented.
Do not treat an enabled desired account as authentication readiness.

The separate [typed creation executor](../identityexec/README.md) now provides
the restricted Linux BusyBox primitive used behind the journal in QEMU. This
does not close the production ownership/transport or credential lifecycle gaps.
