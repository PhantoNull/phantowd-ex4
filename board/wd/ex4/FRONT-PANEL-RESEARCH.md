<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# EX4 front-panel text, LED and alarm research

Status: **partial offline reconstruction, not a driver or hardware qualification**.
The supplied WD 2.13.108 extraction was read statically on 2026-10-16. No WD
program, device command or MCU updater was executed. Contributors must supply
their own lawfully acquired firmware; do not contribute binaries/disassembly.

## Exact selected artifact

`usrsbin/up_send_ctl`, 29,587 bytes, SHA-256
`6979fc69707a777c79dc9b410dff95adae3b664233a1a123673b00597ac34e5f`.
Flattened extraction paths are not a claim about the running filesystem.
Locations below are ELF virtual addresses, not MMIO. For this artifact `.text`
starts at`0x8b20` / file`0xb20`, `.data` at`0x16094` / file`0x6094`.
Original bytes/import relocations and existing saved static text were reviewed;
this is ordinary static evidence, not native REA Evidence or an execution trace.

## Selected string builders

| Request | Dispatch and table | Selected builder |
| --- | --- | --- |
| `SysName` | Class9, entry`0x166b4`; dispatch`0xc180–0xc184 → 0xc2e8–0xc2f0 → 0xad00` | `0xad00–0xad98` |
| `FanSpeed` | Class28, entry`0x168e4`; dispatch`0xc218–0xc21c → 0xc438–0xc448 → 0xac60` | `0xac60–0xacf8` |

Both copy the argument with `strcpy`, test for empty input, obtain `strlen`,
copy that many raw bytes into the outgoing buffer with `strncpy`, append a
terminator and submit an IPC length of`n+6`. Empty text exits without submission.
For ordinary nonempty sufficiently short inputs the constructed sequences are:

- `SysName`: `FA 04 01 00 n payload[n] FB`.
- `FanSpeed`: `FA 04 83 00 n payload[n] FB`.

Here `n` is a **byte count**, stored into one byte, not a character/glyph count.
Neither selected builder converts encodings, interprets RPM or enforces a
payload byte bound. The `SysName` entry contains20 at`0x166c4` (entry+`0x10`);
the handler does not load/check that field. It is not an enforced LCD limit.

Independent instruction anchors: `SysName` calls `strcpy` at`0xad10`, `strlen`
at`0xad28`, `strncpy` at`0xad74`, IPC at`0xad90`; corresponding `FanSpeed`
calls are`0xac70`, `0xac88`, `0xacd4`, `0xacf0`. Both allocate`0xd0` stack
bytes, place the outgoing frame at`sp+0x80` and payload at`sp+0x85`. Arithmetic
therefore places the final marker for length75 at`sp+0xd0`, reaching the saved
register area. This is static bounds inference, **not an executed crash,
exploitability claim or observed device incident**. Do not run the legacy
helpers with crafted input to reproduce it on a NAS.

The independently mapped `fan_control` path formats `%drpm` and invokes
`FanSpeed` at`0x96d0–0x96e8`. This is display publication, distinct from the
binary `FanControl` actuator request. Published numbers can already include
the [legacy nominal substitutions](THERMAL-RESEARCH.md); display text is not
physical RPM, calibration, fresh telemetry or command-application evidence.

## LED ownership and selected alarm arbitration

The separate supplied `usrsbin/led`, 26,307 bytes, has SHA-256
`1c7a85c328699d2d3f4241efc0fc3ac992da94b00641531a337559c048ea0aff`.
Its `.text` begins at `0x8b30` / file `0xb30`, `.rodata` at `0xc538` /
file `0x4538`, `.data` at `0x16094` / file `0x6094`. A second independent
original-byte review cross-checked the selected paths described here.

**Ownership correction:** calling this an exclusively MCU-driven LED utility
would be inaccurate. The selected alarm-output helpers call imported SoC
register read/write wrappers, whereas other paths publish MCU `ErrStatus`
requests. Generic `ledCtrl.sh` with an `a3g_led` interface is a third, different
evidence source. Neither one interface nor program naming proves exclusive
physical ownership of every EX4 light.

The cached-state classifier at `0x9078–0x93ec` has these selected outcomes:

| Result | Condition observed in this path | Not established |
| --- | --- | --- |
| 2 | Exact XML text `1` for device error, overtemperature, undertemperature or fan-not-working | Physical fault, current valid sensor or portable product severity |
| 1 | Recognized later volume/USB/power/backup/UPS/reboot flags, or LAN text containing `down` | Complete source census or a coherent current alarm snapshot |
| 0 | No recognized condition obtained by the selected tests | Healthy/complete/fresh system or permission to clear an alarm |

The LAN check is `strstr("down")` at `0x92ec`, not an exact state comparison.
The classifier initializes a buffer once and ignores XML getter return values;
it establishes no source generation or age. These flags must not replace
qualified sensor/storage observations in PhantoWD.

The selected application routine `0xa434–0xa4c4` first checks access to
`/tmp/system_ready`. Without it, the routine returns. With it, preliminary
output calls occur at `0xa458` and `0xa464`, separated by an unchecked nominal
200,000-microsecond sleep, **before** classification at `0xa478`:

- Class 2 selects helper `0xa13c`; class 1 selects `0xa238`, independently of the
  subsequently read LED-enable preference.
- Only class 0 checks whether `/system_mgr/power_management/led_enable` is 1:
  it then selects `0xa3b4`, otherwise `0xa338`.

This establishes preference override in the **final branch selection**, not
uninterrupted output or global alarm dominance. The exact firmware-updating/
downloading path calls `0xa2b8` directly at `0xc010`, bypassing this routine.
Other direct output paths also need lifecycle review before a product policy.

For class 2, the selected helper uses an off operation for mask `0x20000000`
and a blinking operation for `0x10000000`; class 1 uses an on operation for the
latter. Calls pass selectors `0x10100`/`0x10108` into helpers `0x9f54`/`0xa048`,
which read/modify/write through `LIB_Read_CPU_Register`/`LIB_Write_CPU_Register`.
These are **static arguments**, not qualified physical colors, pin wiring,
polarity or successful application. Reuse of broad register writes is not a
replacement-driver design. No GPIO request, MMIO access or DTS change follows.

An explicit manufacturing-mode hypothesis was rejected during review: although
main records the existence of `/tmp/mfg_mode` in a global flag, these selected
low helpers do not test that flag. Their zero-selector early exits are not
manufacturing suppression. Broader manufacturing effects remain unqualified.

## MCU error-state publication is a separate boundary

`up_send_ctl` table entry `0x1695c` / file `0x695c` selects class 12/command `0x55`;
dispatch `0xc230–0xc244` reaches handler `0x9344`. This handler maps event codes
to **compact selector bytes**, not a bitmask. Examples from explicit comparisons:

| Event code | Encoded selector | Selected legacy label |
| --- | --- | --- |
| 1 / 2 | 25 / 26 | System over/under temperature |
| 29 | 9 | Fan not working |
| 3 / 4 | 30 / 27 | Drive SMART failure / volume failure |
| 5 / 1004 | 31 / 32 | Pending thermal shutdown / high system temperature |
| 2032 | 10 | Standby |
| 2020 or 6 | 52 | Shared selected event branch; not a physical shutdown receipt |
| 2033 | 54 | Encoded event, not bit 54 |

These are a selected mapping, not a complete protocol event catalog. Numeric
parsing at `0x95a0–0x95c4` and `0x98d8–0x98ec` uses decimal `strtol` without
end-pointer/overflow checks; the operation is stored as a byte without a general
0/1 check. The ordinary no-text request is `FA 55 selector operation FB` at
`0x9ad4–0x9ae4`. Optional-text branches instead use a one-byte length plus raw
text, without an overall text bound visible in this selected path.

Optional arguments are required only when the **full parsed operation equals 1**.
Thus a representable operation 257 can publish byte 1 while bypassing that check;
numeric prefixes and malformed operation text can also differ from the intended
strict set/clear contract. These are static parsing/truncation inferences, not
executed malformed commands or observed MCU behavior. Target-libc overflow is
unqualified. Do not reproduce these cases on a NAS.

The handler discards the IPC result; main independently returns 0 at `0xc25c`.
CLI exit 0 therefore does not establish queue success, much less transport ACK,
per-event application or a physical LED state. The replacement must use typed
events and explicit boolean set/clear, bounded event-specific payloads and
separate submission/application receipts. Preserve alarms on source loss or
uncertain application; never clear them merely because a cached getter failed.

## Software prerequisite and remaining gates

[Internal text preparation](../../../src/phantowd-api/internal/frontpaneltext/README.md)
now rejects empty/oversize/non-printable/non-ASCII input without truncation,
under an explicit caller limit and no default hardware profile. It prepares
private requested text only. It cannot send a frame or change an alarm/display.
Its255-byte representation ceiling and ASCII contract do not qualify the MCU.

Required before a physical implementation:

1. Qualify the exact board/controller revision and profile, payload byte limits,
   actual glyph repertoire/width, multibyte behavior, clipping and clear semantics.
2. Complete protocol integrity, delayed/duplicate reply and asynchronous alarm
   interpretation; do not treat the generic ACK as a command-specific receipt.
3. Keep requested, submitted, acknowledged and independently observed state
   distinct. A displayed requested/nominal speed never replaces measured RPM.
4. Establish bounded transport ownership, controller loss and verified settlement,
   then alarm priority over cosmetic text/settings. No blind retry or restart.
5. Complete the split SoC-GPIO/MCU LED ownership and global alarm arbitration,
   including boot/update/shutdown/direct paths. Qualify a narrow kernel/GPIO
   interface and exclusive ownership rather than porting broad register writes.
6. Run host/disposable-QEMU boundary/fault cases before separately approved
   physical tests with independent thermal observation and recovery.

Actual MCU glyphs, framing-byte handling, MCU-side limits, LCD/LED behavior,
global alarm arbitration and physical command application remain unqualified. No
firmware update, active default or hardware authorization follows from this note.
