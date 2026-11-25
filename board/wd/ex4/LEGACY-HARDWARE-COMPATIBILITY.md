<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# EX4 legacy hardware compatibility map

Static findings reviewed on 2026-11-08. This is a reconstruction and contributor
handoff, not an installation guide or hardware qualification. Research artifacts
remain **compile-only, flashable=no**. No device, firmware program, register or
flash operation was performed for this analysis.

## Baselines and evidence

Legacy input: `My_Cloud_LT4A_2.13.108.bin`, 114450460 bytes, SHA256
`db1ee3e733d2cbb945e593b99a4c3972e816d3b8d80a9bdfa908ddc774401aa0`.
The package-bound SquashFS SHA256 is
`89848a0a12fc3600a649883e4008bc61d96a5a91b55f1a94d4c1dc1ae771e243`.
This identifies the analyzed package, not the runtime contents of every EX4.

Custom comparison: `v0.1.0-research.1`, commit
`1cbe30932f900dc0731f2dca03e8b4d62b355db8`, tree
`6b2829a754c0842a2340dded471c9baf372caa1c`.
Later code must be checked separately before claiming a gap is closed.

REA/GNU ARM disassembly and ordinary static ELF/text parsing covered 22 native
artifacts, with 44 complete REA operations and unchanged input hashes. Selected
archive-member reads authenticated 68 files, including ramdisk text. These are
static observations, not recovered original C, runtime traces or MCU firmware.
No proprietary binaries, disassembly, device dumps or operator data are included.

## Functional comparison

| Area | Legacy software path recovered | Tagged custom boundary / remaining work |
| --- | --- | --- |
| SATA | Four-slot power/presence dispatch through I2C, staggered power-on, hotplug and separate standby daemon | Physical block/SATA exposure disabled; controller/bay binding and production volume lifecycle remain unqualified |
| Ethernet | Two logical ports, DHCP/static addressing, bonding, VLAN, IPv6, resolver refresh and WOL dispatch | B3 provides bounded link observations; persistent configuration/apply/rollback and full port identity remain unfinished |
| Fan | MCU mode command, UART thermistor path, SMART disk input and separate register-bit tach polling | Passive MCU decoder and SoC thermal observation do not provide a fan/tach product service |
| LEDs | Native paths mix SoC register helpers and MCU error-state commands | Model-qualified pin/polarity/color mapping and active ownership remain incomplete |
| Display | Queued MCU transport, text/IP/status constructors, network updates and web settings | Payload semantics, transport lifecycle and web-to-hardware integration remain incomplete |

The historical B2 trials described in [board notes](README.md) reported left
jack -> eth0 and right jack -> eth1 in that narrow research configuration.
This analysis did not repeat those trials or establish the legacy egiga binding,
factory identity, sustained link stability or applicability to another revision.

## Storage identity and mount selection

The native path is not simply current sd-letter -> HD-letter. `hdVerify` loads
hidden volume metadata, reads its logical `volume` number and invokes device-name
reconciliation. A library table maps numbers 1..4 to HD_a2..HD_d2; the mount call
receives the current data device separately. A retained accepted number therefore
selects the same destination independently of that device argument.

A roaming-marked path can instead allocate the first free number 1..4 when the
requested number is occupied. That can change the mount destination; a physical
bay move is not proved to trigger that path. The scoped full-occupancy scan has
no distinct refusal result. Upstream validation, copy precedence, RAID admission
and persistence of renumbering remain partial. Do not promise universal disk
roaming or automatically import recognized metadata.

The I2C power/presence library uses distinct bookkeeping, output and presence
bit encodings. Restart ends with a whole-byte write; a zero CLI result does not
verify actual power. The program named `set_pwm` includes disk standby/wake,
not evidence of a Linux fan PWM interface. Legacy mount branches include
`data=writeback,barrier=0`; these are not replacement data-integrity defaults.

## Network lifecycle

The native resolver refresh truncates and rewrites resolver state from XML;
DHCPv6 callbacks have another writer. Neither ordering nor successful output is
proved by CLI exit 0. Address changes can cause broad SMB/service restarts.
The WOL default helper attempts both logical ports, with bonding-dependent MAC
selection; that does not prove wake capability or retained PHY power.

Two source inconsistencies must not be copied: second-port MTU handling tests
the first port's enable variable, and one dual-DHCPv6 VLAN path uses VID0 for
port1 instead of VID1. No live manifestation was observed.

## MCU, display and fan semantics

The requested serial settings are ttyS1/19200/8N1. All 82 TX and 38 RX table names,
order and four template bytes match the custom passive catalog. These bytes are
not full frames or complete payload semantics. The inspected receive routine
contains no checksum calculation/comparison; MCU-side integrity remains unknown.

`FanControl` accepts numeric modes 0..4. `FanSpeed` belongs to a string-carrying
family; its name is not evidence of actuation or measured RPM. Display-like
strings, supplied temperature values and actual sensor observations must remain
separate concepts. The ACK producer writes a constant global XML value; the
consumer checks that value without a request-specific comparison. It is not a
transaction-correlated acceptance receipt.

The bounded automatic fan loop has four levels, history-dependent candidate
updates and hysteresis over a derived temperature input. Other observed paths
reuse a cached board reading after zero, normalize selected disk readings and
exclude some model-gated inputs from cooling despite reporting them. Warning,
safing and pending-shutdown are a separate state machine; its final poweroff
consumer and all alternate modes remain incomplete. These constants are not a
calibrated replacement fan profile. Thermal implementation/testing is not opened
by this document or made a research-release gate.

## Next work and acceptance evidence

- **Storage first:** reconcile missing, cloned, conflicting and full inventories
  with existing volume/discovery/mount owners. Keep logical identity separate
  from bay, kernel name and export path; no implicit import or fallback to an
  empty local directory when storage disappears.
- **Network:** one source-aware resolver authority, deterministic lease replacement,
  explicit write failure, bounded apply/confirmation/rollback and affected-service
  notification. Same-address renewals should preserve sessions.
- **MCU:** finish remaining error/RTC/alarm/disk constructor families and callers.
  Define explicit unavailable/uncertain outcomes, bounded requests and parser
  limits; do not invent request correlation unsupported by the wire evidence.
- **LED/display:** bind active model branches, pins, priorities, text encoding,
  lengths and timeout policy before exposing product controls.
- **Fan research:** retain the recovered branch model; finish remaining failure,
  unit and shutdown-consumer evidence without copying brand gates or unaged
  cached readings. Physical behavior remains outside this offline task.

Host/synthetic tests establish software contracts, not physical disk compatibility,
fan safety or installability. No new parallel owner, installer, flash operation,
rescue qualification or automatic hardware activation follows from this map.

## Native anchors for further inspection

VMAs below refer to the named original ELF, not live hardware addresses.

| Artifact | Static anchors |
| --- | --- |
| hdVerify | Metadata parser 0xce78; volume field 0xcf60..0xcf84; mount lookup 0xaeec..0xaf78; roaming allocator 0x9b94..0x9c0c |
| libhdVerify.so | mountPoint table 0x123bc; mountAction 0x2500; readVolumeInfoXml 0x4490; insertion 0x73e8 |
| libhwshare.so | SATA control 0xa94; restart 0xd8c; presence 0xe08 |
| network | Resolver option dispatch 0x9d68 ->0x9eec -> writer 0x8dec |
| set_wol | Default two-port dispatch 0x90f0..0x9104 |
| up_send_ctl / up_read_daemon | FanControl 0x90d0; string-family FanSpeed 0xac60; ACK producer 0x9008..0x9060 |
| fan_control | Auto loop 0xa8ec..0xad2c; normalization 0xa130; warning/pending-shutdown 0x9c1c |

For current product scope and task dependencies, use the
[implementation status](../../../IMPLEMENTATION-STATUS.md) and
[roadmap](../../../ROADMAP.md). Static reconstruction closes only the explicitly
bounded questions above, not their enclosing milestones.
