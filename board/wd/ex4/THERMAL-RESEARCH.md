<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# EX4 thermal-control research boundary

Status: **partial static reconstruction, not a cooling implementation**.
These observations concern supplied WD 2.13.108 ARM artifacts, inspected offline
on 2026-10-15. No vendor program or hardware command was executed. Function
locations are ELF virtual addresses; separately labelled MMIO addresses below
are computed static targets, not validated hardware accesses.
QEMU software tests cannot qualify the EX4 fan, sensors or autonomous controller.
Independent static review cross-checked the command dispatch and selected boot,
GPIO and temperature/cache paths; it did not qualify the complete regulator.

## Artifact identity

The supplied extraction uses flattened `usrsbin/`, `usrlib/` and `script/`
directories; these names are not claims about the running root filesystem.

| Artifact | SHA-256 |
| --- | --- |
| `usrsbin/fan_control` (22,983 bytes) | `5a49f1b6c6a9fe83c5cc2600a217b9fe5a33bb0fca9605e5183d660aa355124a` |
| `usrlib/libtemperature.so` (9,799 bytes) | `5b9c7dc6181f6bb2c663b56a4f9d77222dcc5a92e30d7804995f144b4b299118` |
| `usrlib/libshare.so` (51,215 bytes) | `78abf720bc3898795ac07056d7cabd5ac50fbc901790c4a8bb059ec4d4087bd8` |
| `usrsbin/up_send_ctl` | `6979fc69707a777c79dc9b410dff95adae3b664233a1a123673b00597ac34e5f` |
| `usrsbin/up_send_daemon` | `5c12e7483f03989f42fd3b8bce71ba70d62e2a15e96503e4311e7eda3f6a0668` |
| `script/system_init` | `b7d7a62ca8d5a0c2d7d67c2c148e5cc637d9975eecf8e0d362f1e5fdd533c379` |
| `script/shutdown.sh` | `9846c1c5a2f29951fa64bbc158067b2c62afce3404b0ce046f5b92ba9e7c88e8` |

This is not a complete firmware-carrier authenticity check. Contributors must
supply their own lawfully acquired artifacts. Do not contribute vendor binaries,
disassembly or raw device captures to this repository. GNU `readelf`, `strings`
and ARM `objdump` were used statically; this is not a native REA execution trace.

## What the selected paths establish

| Path | Observed behavior | What it does not establish |
| --- | --- | --- |
| Boot script, lines1064–1077 | Calls the boot fan routine, then a long-running regulator; a manufacturing-temperature branch selects a different mode | Startup-safe cooling before that late init step, or sustained safety |
| Boot routine, `fan_control` `0xa85c–0xa8d4`; caller `0xb0d4–0xb170` | Initial data at `0x1537c` selects level1, LOW. Only a positive fan-state result reaches initial level3, HIGH, at `0x15384`; failure records an alert/marker | Actual RPM/duty, MCU acceptance, immutable runtime configuration, or safe maximum |
| Setter, `libtemperature` `0xb84–0xbc0`; caller `fan_control` `0x9ac8–0x9b1c` | Formats a controller-helper request, invokes it and sleeps3seconds. Caller publishes the requested level to IPC without checking completion | A confirmed applied speed or successful hardware operation |
| Fan-state wrapper, `libtemperature` `0xbcc–0xbd8` | Selects the GPIO helper with register selector/offset `0x10154` and mask `0x80`, not the separately present UART helper | Physical pin mapping, electrical polarity or RPM |
| GPIO state helper, `0x103c–0x1084` | Clears status, then makes up to five masked reads with10ms waits; returns0/1 | A fresh tachometer measurement or fully understood register-error behavior |
| Board-temperature reader, `0xd04`, `0xe94–0xf3c` | Requests sensor2, waits300ms, reads the locally cached selector4 value; tries up to three times while the parsed number is zero | A request-bound fresh sample. Subprocess/parse statuses are not checked here; these waits are not a total I/O deadline |
| Temperature wrapper, `fan_control` `0x9270–0x9314` | A zero result reuses the previous nonzero value at `0x153b4`; no age check appears in this wrapper | Comprehensive sensor failure detection, freshness, calibrated units or trustworthy current temperature |
| Shutdown script, lines10–12 | Terminates the fan regulator, temperature monitor and hibernation helper | A qualified cooling handoff during shutdown or power-off completion |

The initialized boot values are **LOW then conditionally HIGH**, not MEDIUM/MAX.
Static initial data is not proof of every reachable runtime configuration.
The exported `LIB_Get_Fan_Speed` at `0xb7c–0xb80` simply returns zero in this
library. The separate `getFanrpm` path is reconstructed below; neither the
symbol name nor the boolean GPIO result establishes calibrated physical RPM.

## Controller request boundary

`up_send_ctl` main dispatch `0xc1f8–0xc1fc`, `0xc424–0xc430` selects the
FanControl handler at `0x90d0`, not the nearby handler at `0x8fc8`.
The former requires three arguments and a decimal result in0–4. It does not
check conversion-end or `errno`; malformed text can therefore be interpreted
as a number rather than rejected. Help labels0–4 as Stop/Low/Medium/High/Highest;
those are labels, not measured cooling capability.

The handler's seven-byte IPC payload has the form `FA 02 00 n 00 00 FB`.
The GetThemister handler at `0x91d4` uses a separate seven-byte request with
prefix `FA 03 08`; selectors3/4 instead read XML state locally. For transmitted
selectors, the decimal argument is truncated to a byte without the FanControl
range check. This is protocol evidence, **not an instruction to transmit**.

The IPC wrapper `0x8ee4–0x8fa8` copies the supplied bytes. The sender forwards
them individually at `0x8b6c–0x8b94`. No integrity-field calculation appears in
these selected builders/forwarders. Literal zero bytes must not be named or
validated as checksums on that evidence. The existing generic ACK flag does
not establish a per-command execution receipt, acceptance or safe retry.

## Tachometer and register-error boundary

`libshare` `getFanStatus` at `0x7eb0–0x7ec8` reads selector `0x10150` and
extracts bit7. `getFanPluse` at `0x7ecc–0x7fbc` counts changes of that bit,
starting with a synthetic previous value1. It stops at an elapsed comparison
of at least1,000,000microseconds or200,000 iterations. It does not sleep between
samples. Each wall-clock timestamp is truncated to32bits, sign-extended, then
subtracted in64bits; clock changes/sign-boundary crossings can distort the
interval. Time/read failures are not represented as distinct sample quality.
This is not a guaranteed one-second, monotonic, calibrated measurement window.

`getFanrpm` at `0x7fc0–0x7fd8` returns `15 * count` for count greater than1,
otherwise zero, without normalizing by the actual elapsed interval. Neither
this factor nor the variable names qualify transitions per revolution.

The regulator at `0x9624–0x9848` adds another transformation. After a raw value
differs from its stored value, and only for a strictly positive value with
level1–4, the following inclusive bands select whether it is retained:

| Requested level | Raw estimator band retained | Positive out-of-band replacement |
| --- | --- | --- |
| LOW | 750–1200 | 1025 |
| MEDIUM | 1150–1750 | 1450 |
| HIGH | 1600–2350 | 1985 |
| MAX | 1900–2900 | 2355 |

These are **legacy display/publication transformations, not acceptable product
RPM limits**. Raw/stored equality exits before this normalization. The selected
result is published to the MCU display and a temporary RPM file; even a changed
value can be nominal rather than measured. Do not copy this behavior into
health reporting or use an apparently plausible legacy number as tach evidence.

The CPU register wrappers add `0xf1000000` to their selector. The exact read/
write helpers (`0x7df8–0x7e90`, `0x7d2c–0x7dc0`) open `/dev/mem`, map one
dynamically sized page read/write and shared, then access a32-bit word.
Read returns zero for open/mapping failure as well as for a genuine zero word.
Write and its CPU wrapper return zero even on failure. If mapping fails after
opening, the descriptor is not closed on that branch; successful-access cleanup
also ignores unmap/close results. There is no trustworthy error receipt here.

In `libtemperature` `0xf74–0xfcc`, clearing fan status tests for an error value
of `0xff`, not the read helper's zero-on-error result. A failed read can therefore
reach an attempted zero-word write; polling failures can look like no activity.
This is a static failure path, not an observed device incident or a reason to
reproduce the access on hardware.

### Cross-check against the supplied GPL kernel

The nearest WD GPL kernel archive, `linux-3.2.40.tar.gz`, has SHA-256
`bdd034a67b011a850ad4d4a2eb76e3c171f1e0a9442496318ad80bf127e93f9e`.
Only selected source members were read, without materializing a source tree
or building a kernel:

- `arch/arm/plat-orion/mv_hal/gpp/mvGppRegs.h`: selector `0x10150` is bank1
  data-in; `0x10154` is bank1 interrupt cause.
- `arch/arm/plat-orion/gpio.c`: input offset `0x10`, latched edge-cause `0x14`;
  the logical GPIO reader additionally accounts for input polarity.
- `arch/arm/mach-kirkwood/irq.c` and `include/mach/kirkwood.h`: high-bank
  gpiolib base32 and register offset `0x10140`. Under this mapping, bank1 bit7
  corresponds to **GPIO39**, not GPIO7.

The binary's computed MMIO targets are `0xf1010150` and `0xf1010154`.
Source definitions support their interpretation; the archive alone does not
prove which source path was compiled. Physical fan wiring, pinmux, polarity,
interrupt ownership and board revisions remain unqualified. The kernel's
logical GPIO value is not necessarily the raw data-in bit. This evidence does
not authorize `/dev/mem`, a GPIO request, interrupt reconfiguration or a DTS
change on the NAS.

## Replacement requirements and remaining work

Do not port the legacy zero-sentinel cache or optimistic requested-speed state
as if either were a safety guarantee. This investigation adds no controller,
serial opener, transmitter, sensor conversion or active default to the product.

The next offline pass can proceed without hardware:

1. Qualify the mapped tach path's board association, pinmux/polarity, actual
   elapsed-time behavior and transitions per revolution before selecting a
   replacement provider. Preserve read failure separately from stopped fan;
   do not adopt broad `/dev/mem` mappings or whole-register status writes.
2. Trace thermistor lookup, index bounds, unit conversion and calibration through
   receive processing. Map HDD temperature normalization, missing/non-WD-drive
   handling, hysteresis, overheating counters and the actual shutdown consumer.
   Legacy constants are not qualified product thresholds.
3. Trace `set_pwm` and hibernation interactions before assigning exclusive
   cooling ownership. Its filename and presence in init do not prove its role.

Before implementation/activation, the reviewed thermal contract must specify:

- distinct requested and observed state; transport ACK is not application proof;
- sample identity, monotonic age and validity, with no silent last-good-as-current;
- raw count/elapsed/calibration provenance for RPM, no nominal substitution,
  and explicit read/clock/overflow failure rather than zero-as-error;
- explicit unavailable/stale/out-of-range sensor, controller loss, stuck fan and
  regulator-crash behavior; externally qualified safe response remains a gate;
- startup and shutdown ownership/handoff, including faults before normal init;
- hysteresis, bounded settling and deadlines, without restart/retry hiding faults;
- host fixtures for time/age/range/identity/fault transitions and bounded memory;
- a separate hardware plan with independent temperature/tach observation,
  stop conditions, sacrificial media and recovery before advertising safety.

No numerical threshold, safe command or longer NAS boot is approved here.
See [M7 qualification](../../../ROADMAP.md#m7-ex4-board-controller-and-thermal-qualification)
and the [board scope](README.md).
