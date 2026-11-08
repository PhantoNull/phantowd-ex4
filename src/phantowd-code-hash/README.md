# Fixed code hash worker

Internal ARMv5 helper for an explicitly constructed service Owner. It reads
1–256 inherited regular read-only files (at most 64 MiB total) and emits a
bounded SHA-256 frame. It opens no input paths and writes only stdout.

The caller must admit its exact program digest from trusted build/release
inputs, retain all original files through verified settlement and compare every
digest with its original plan. A digest observation grants no execution or
storage authority. The package reserves disabled identity `59999:59999`.

The Go reader is single-use, preserves cancellation and refuses partial results.
Ordinary runtime inspection remains Go-only. Service-Owner integration and
product startup require separate qualification; research outputs are `flashable=no`.

The recipe recompiles three unmodified Nettle C units from its configured,
pinned Buildroot dependency. Original wrapper code is Apache-2.0; combined
artifacts retain Nettle's LGPLv3-or-later terms and source/license requirements.
