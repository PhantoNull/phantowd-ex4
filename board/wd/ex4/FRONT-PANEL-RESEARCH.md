<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# EX4 front-panel text research boundary

Status: **partial offline reconstruction, not a driver or hardware qualification**.
The supplied WD2.13.108 extraction was read statically on2026-10-16. No WD
program, device command or MCU updater was executed. Contributors must supply
their own lawfully acquired firmware; do not contribute binaries/disassembly.

## Exact selected artifact

`usrsbin/up_send_ctl`,29,587bytes, SHA-256
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
5. Map EX4 LED ownership/thermal overrides from the actual MCU `led` binary,
   not generic `ledCtrl.sh` using a different `a3g_led`/`led_color` interface.
6. Run host/disposable-QEMU boundary/fault cases before separately approved
   physical tests with independent thermal observation and recovery.

Actual MCU glyphs, framing-byte handling, MCU-side limits, LCD/LED behavior,
alarm arbitration and physical command application remain unqualified. No
firmware update, active default or hardware authorization follows from this note.
