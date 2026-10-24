# Offline rescue body review, 2026-10-22

Question c remains unresolved. The available inputs do not independently assign
the rescue body's inner components or reconcile them with the fixed-offset
reader. This note does not qualify recovery, a writer or installation.

## Scope and method

The original review read existing local files, saved reports, public GPL text
and ELF bytes only. It did not run target programs or access a NAS, serial,
MTD, MMIO or network device. This publication preserves that review without
repeating it; it does not qualify recovery, installation or a writer.

F denotes an externally supplied `My_Cloud_LT4A_2.13.108` analysis directory.
G denotes an externally supplied `WDMyCloud_EX4_GPL_v2.12.127_20181219` GPL tree.
Neither firmware binaries nor local analysis inputs are included in this repository.

Original review-note SHA-256: `01904d6daee6918056732519e6fd715ae24bccf45af07afea004eeeaef700246`.

## Newly checked original identities

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| F/archive/My_Cloud_LT4A_2.13.108.bin | 114450460 | db1ee3e733d2cbb945e593b99a4c3972e816d3b8d80a9bdfa908ddc774401aa0 |
| F/analysis/rootfs-mtd3-full-extracted/usrsbin/rescue_fw | 18195 | 27763bbd964f6ebd639c9d5e970ffa72fe192a280aebd60fafd2b8e3dfce0677 |
| G/firmware/module/crfs/usrsbin/rescue_fw | 18195 | 27763bbd964f6ebd639c9d5e970ffa72fe192a280aebd60fafd2b8e3dfce0677 |
| F/analysis/rootfs-mtd3-full-extracted/usrsbin/upload_firmware | 38963 | d616668b4544835d14d2105906851201d89c5c077dce7402a2684cfcb27ca3aa |
| F/analysis/ramdisk-full/usr/sbin/chk_image | 9923 | c8ef7fb5c21d9f51844f3a35e7ddd80d1873b204e805a865c5fc761b0804f600 |
| F/reports/upload_firmware-full-disassembly.txt | 256360 | e18604822a0654c6e7c46b1b81801b3f82d944ee860723855ff8b129c3feaf5d |
| F/reports/chk_image-disassembly-2.13.108.txt | 38073 | 938c5a413815f69697828a39e36006ff260a90bfca22bd9b57e016b47412fa48 |
| G/firmware/merge/merge | 13884 | 2c51da6604adf0f4c0bc8351545163e4b969fed239b0d429afd4eb476215e230 |
| G/firmware/module/create_image.sh | 75 | 557bfdfc8e47dcb335ae352245788b0713658ea406e3cf5e5baf0cb897e9667b |
| G/firmware/ramdisk/create_ramdisk.sh | 1071 | 893846405fa35959b7b606c231e9f44f4f7f1645e1fa1b107b1a49a3d39ca2b9 |

The final rescue_fw hash parity removes the historical September20 limitation
that its final-release identity had not independently been checked. It does
not supply a rescue payload or validate any physical behavior.

## Producer and readers

1. F/archive contains one regular input: the normal update BIN above. Original
   bytes at 0x30 are `55 aa 4c 69 67 68 74 6e 69 00 55 aa`; bytes at 0x32 are
   `4c 69 67 68 74 6e 69 00 55 aa 00 14`, not the rescue magic. The normal
   container manifest independently describes kernel, ramdisk, mtd3, defaults
   and MCU components; this cannot be substituted for an inner rescue layout.
2. Existing static evidence traces upload_firmware 0xbe80/0xbd44 -> classifier
   0x9dc0 -> rescue type2 -> validator 0xd2b4 (call 0xc39c) -> writer 0xdabc
   (call 0xc428) -> header merger 0xd544 (call 0xdb28). Report line anchors:
   1080,3176,3503,3537-3538,4469,4633. A fresh original ELF32LE/PT_LOAD
   comparison matched 1191 instruction/literal words in [0x9dc0,0x9f00),
   [0xbe80,0xc50c),[0xd2b4,0xdd84). This confirms the saved code/report
   agreement, not every indirect/transitive behavior. This is a preexisting
   rescue input consumer; the known merger rewrites only its 2 KiB header.
3. The identity/length/XOR reader is corroborated by exact final/GPL rescue_fw
   parity and the earlier offline reader evidence summarized in
   [NAND-RECOVERY-RESEARCH.md](NAND-RECOVERY-RESEARCH.md): 2 KiB header, length at0x14, XOR at0x18, body at0x800;
   packed bad-block/OOB-omitting NAND reads. This review did not reconstruct a
   new native dossier for it; no saved local rescue_fw disassembly was selected.
4. The other reader, chk_image 0x8eb0, is independently anchored: all73 words
   in [0x8eb0,0x8fd4) match original ELF mappings. Report lines581-641 show
   requested10MiB dump at0x8ee4, seek at0x8f24-0x8f30, literal0x501000 at0x8fcc,
   and1KiB copy loop through0x8f74. Results/counts remain unchecked as described
   in NAND-RECOVERY-RESEARCH.md. 0x501000 =5MiB+4KiB is only an observed seek;
   it does not identify the preceding byte ranges. Conditional remaining
   length0x4ff000 is arithmetic, not component evidence.
5. G/firmware/merge contains merge,uImage,uRamdisk,image.cfs,default.tar.gz,uP.bin.
   create_image.sh lines3-4 build SquashFS then call image_checksum;
   create_ramdisk.sh builds ext2/gzip and invokes mkimage for a ramdisk.
   Neither visible script constructs a rescue body. A bounded text search of
   G for rescue_fw/LigRescure/rescue firmware in *.sh,*.c,*.h,*Makefile*,*.txt
   returned only reset_default_reserve_file.txt:14. This is not a global absence
   proof: extensionless scripts, binaries and nested archives are outside that
   text-search coverage. Saved analysis identifies merge as the normal update
   generator; its filename alone provides no rescue-producer evidence.

## Exact remaining dependency

Need an already available, independently identified rescue object and a
non-executing producer/boot-consumer trace that assigns every proposed inner
range (including headers, padding, lengths and checksums). Present ordinary
update components, magic matches, merger labels and reader offsets do not
supply those assignments. No request for live capture or hardware action is
made by this review. Producer provenance, relation to0x501000, stock bootloader
handoff/ECC and physical recovery remain open.

## Reproduction, local reads only

These commands do not execute the named firmware binaries:

```powershell
$f = 'path\to\My_Cloud_LT4A_2.13.108'
$g = 'path\to\WDMyCloud_EX4_GPL_v2.12.127_20181219'
Get-ChildItem -LiteralPath ($f+'\archive') -File | Select-Object Name,Length
Get-ChildItem -LiteralPath ($g+'\firmware\merge') -File | Select-Object Name,Length
Get-FileHash -Algorithm SHA256 -LiteralPath ($f+'\analysis\rootfs-mtd3-full-extracted\usrsbin\rescue_fw'),($g+'\firmware\module\crfs\usrsbin\rescue_fw')
Get-Content -LiteralPath ($g+'\firmware\module\create_image.sh')
Get-Content -LiteralPath ($g+'\firmware\ramdisk\create_ramdisk.sh')
rg -n -H -uuu --no-messages -i 'rescue_fw|LigRescure|rescue firmware' -g '*.sh' -g '*.c' -g '*.h' -g '*Makefile*' -g '*.txt' $g
Get-Content -LiteralPath ($f+'\reports\chk_image-disassembly-2.13.108.txt') | Select-Object -Skip 580 -First 63
rg -n '^\s*(9dc0|be80|c39c|c424|c428|d2b4|d544|db24|db28):' ($f+'\reports\upload_firmware-full-disassembly.txt')
```

The original-word check maps each report address through exactly one ELF32LE
PT_LOAD file-backed range; compare the report's little-endian32-bit word with
the original file word. Exact checked ranges/counts are recorded above. An earlier offline check covered a smaller712-word consumer selection;
this review expanded the updater selection through the separate validator,
header merger and writer. These counts describe static comparisons only.
