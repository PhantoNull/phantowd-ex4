# Internal front-panel text preparation

M7.4a software prerequisite, **not an LCD driver or controller**. `Prepare`
accepts a nonempty string of printable ASCII bytes (`0x20..0x7e`) within an
explicit caller-declared byte limit. Output preserves every byte, including
spaces. Oversize, empty, control, NUL, framing and non-ASCII bytes are refused
with a fixed error and zero result; no truncation, escaping or transliteration.
Empty text is not an implicit clear command.

The limit must be1..255. **255 is only the selected legacy builders' one-byte
representation ceiling**, not a qualified EX4 payload size, LCD width or glyph
count. There is no default20-byte profile: a table value20 is present in the
legacy `SysName` entry but its selected builder does not enforce it. ASCII is
an intentionally narrow software input contract, not hardware qualification.
A future trusted model/controller profile must separately establish its actual
byte/repertoire limits and refuse an absent or incompatible profile.

`Text` is immutable/private; its zero value is invalid and JSON is refused.
It is requested text, never observed display state. Text such as `1025rpm`
remains text, not a tach measurement or proof that a fan command was applied.
The component provides no profile selection, numeric formatting, provenance
conversion, frame encoder, checksums, port access, subprocess, HTTP, persistence,
retry, polling or normal-startup caller. No WD utility is invoked.

Input length is checked before scanning, so runtime work is at most255 bytes.
No per-call allocation is required by the implementation; host allocation tests
are compiler/environment observations, not a complete firmware resource budget.
Errors never contain or retain rejected input.

Host tests cover all256 byte values, every inclusive1..255 limit, oversized
input, UTF-8/control/framing refusal, preserved spaces, private JSON and no
reuse of prior output. Fuzzing compares against an independent rune-based
predicate. An invented-profile fixture is enrolled in the existing standard
QEMU self-test before/after API restart, with two exact receipts required; it
does not create a guest or exercise a physical display. Check implementation
status for which host/ARM checks actually ran on a checkpoint.

Next product gates: trusted board/controller profile, complete protocol and
integrity, bounded transport ownership/settlement, request/application
distinction, alarm priority and qualified physical display behavior. No active
transmission is authorized. See the [static evidence and remaining work](../../../../board/wd/ex4/FRONT-PANEL-RESEARCH.md).
