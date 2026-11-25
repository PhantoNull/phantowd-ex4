# NFS input preparation and experimental QEMU lifetime

On Linux, `PrepareInputs` joins the original NAS policy lease, identity lease
and mounted volume roster for one enabled NFSv3/TCP request. It owns a complete
roster lease and export-root pins. `Check` compares the exact request and
rechecks the original sources. `Close` releases the owned inputs after its caller
verifies service stop. The caller retains both borrowed leases through close.
`NewLinux` transfers the original inputs into one service Owner with a fixed
trusted runtime. The Owner checks inputs independently of the runtime and
requires verified stop and runtime closure before releasing storage. While
attached, the original handle refuses external checks, closure and transfers.
The caller keeps its borrowed policy and identity claims through closure.
The Linux RPC component holds executable references for `rpcbind`, `mountd`
and `rpcinfo`. It starts `rpcbind` before NFSD and `mountd` after confirming
that NFSD is running. It checks both original processes and program readiness,
then reaps the process groups in reverse order before releasing the grants.
`mountd` uses TCP on port 20048. Before publishing exports the runtime
matches the kernel listener inodes to the retained process and refuses UDP,
unexpected owned ports and foreign listeners on the mount port. The same
port must be free before startup and after shutdown. The platform still
selects the ingress interface and NFS destination address in the admitted
namespace. The runtime builds its own nftables input table from the retained
IPv4 export client prefixes. It installs the table before opening ports and
checks all three ports for conflicts before and after table installation. It
checks the table, chain and ordered rules before publication and on health
checks. It permits TCP to the selected address from the selected interface
and sources, plus the local self-probes. It drops other TCP and all UDP on
ports 111, 2049 and 20048. The table stays until verified service shutdown.
The RC0 profile includes nftables and its JSON dependency. The disconnected
QEMU API fixtures have an explicit QEMU-only constructor for existing base
images without nftables. To test actual packet enforcement with a Linux
kernel, run `sh support/test-nfs-firewall.sh /usr/sbin/nft` on a host with
user namespaces enabled.
The full ARMv5 peer runner opens the shipped nft binary and calls
`NewManagedLinux` with the real test interface. It requires the denied
peer to time out on all three TCP ports, the admitted peer to connect,
and a UDP packet to be dropped before the admitted NFS mount and write.
The legacy-base peer mode reports its export-policy scope separately.
The ordinary Linux constructor `NewManagedLinux` composes the controller, RPC
helpers and export manager. It retains the explicit NFSD, namespace and
executable grants before startup, then sequences rpcbind, NFSD, mountd and
publication. It verifies readiness through all three components and verifies
client quiescence, an empty export table and stopped helpers before release.
The platform supplies namespace isolation, RPC socket isolation, network
exposure and the client quiescence check. The managed runtime creates fresh
root-only state on the appliance's original `/run` tmpfs. The shipped
`nfs.conf` directs nfs-utils 2.8.6 to that state for both exports and client
records. The runtime requires that exact configuration and refuses vendor
configuration or drop-ins that could redirect the helpers. Closure removes
only recognized state files after verified stop and refuses stale state on
subsequent construction. The guarded guest uses this constructor for both
lifetimes, checks the actual private tables and confirms the default tables
are untouched. It also proves that rejected partial admission unwinds before
a fresh admission with the same original inputs.
The Linux export component pins `exportfs` and takes the original candidate
from the attached input handle. It starts from an empty table and checks the
exact nfs-utils display of each generated client rule. After verified NFSD
stop, it removes only observed rules from its own candidate and verifies an
empty table before releasing the executable. Unexpected entries require
review and inhibit withdrawal.

Construction captures one typed candidate and fixed trusted backend without I/O.
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
The fixed guest adapter joins original NAS-policy, identity and storage leases
to real NFSD. Both initial planning and running checks read the same policy
claim; operations cannot substitute a configuration. A valid desired update is
refused while the server runs and after stop until verified close releases it.
The client reads over NFSv3/TCP and gets server-side EROFS on creation. Activation
and refused updates leave the stored document unchanged; the parent can publish
a new desired revision after NFS closes. A second explicit lifetime acquires
fresh claims from the same policy/identity/storage Owners, applies saved revision2
and verifies real client read, fsynced write bytes and UID/GID at both views.
Calls on the old closed Owner refuse without disturbing the new server.
The consumer releases its claims; the parent retains the shared Owners and
dataset until both lifetimes have verified stop/close. Only then does the parent
remove synthetic data and close its authorities. This is never an automatic
restart after a failed or uncertain lifetime.
Guest failure reports preserve the nested lifetime's phase and distinguish
deadline, cancellation and parent-context completion without printing private
cause text.
The policy is synthetic guest state: this does not qualify product boot
provisioning or this composition across reboots.
Bracketed owner observations do not establish atomic three-owner admission.
No polling supervisor, HTTP or product activation exists.

Linux `ExportRoots` separately captures original-lease directory metadata
and retains uncertain construction/closure. Native refusal/privacy/model tests
and a guarded ARM fixture cover mixed roots, whole-volume capture, missing and
symlink refusal, parent-close exclusion and replacement/restoration review.
Known disposal after path drift is not uncertain-close recovery; real close
failure injection and the complete fault matrix remain unqualified. Source
capture exposes no descriptor getter; the fixed guest adapter owns protocol
activation separately.
