# lskdd selector 18 table sources

The installed arm64e image supplies a candidate frame that resolves both calls in the selector 18 block. Its method call at `0x100584cc8` selects `IOKit/_IOConnectCallStructMethod` when the table root and byte banks below reach that block. The initializer-to-block transfer remains unknown. [Earlier method ABI audit](live_lskdd_method_abi_report.md) [Related selector 19 frame](live_lskdd_selector19_binding_report.md)

| Role | Original pointer producer | Frame store | Selector 18 use |
| --- | --- | --- | --- |
| Preparatory left bank `0x100e07090` | Rebase at `0x100e74818` minus 12 B | `0x100654a94`, SP+0x50 | `0x100584c08` |
| Preparatory right bank `0x100cb47e0` | Rebase at `0x100e75f90` | `0x100654a94`, SP+0x58 | `0x100584c1c` |
| Method left bank `0x100d3f720` | Rebase at `0x100e75ef0` minus 4 B | `0x1009e910c`, SP+0x78 | `0x100584c7c` |
| Method right bank `0x100e06f90` | Rebase at `0x100e76568` minus 8 B | `0x1009e9118`, SP+0x80 | `0x100584c90` |

The table root in X28 is `0x100e2ce30` on the inspected small-frame route. For each byte input i, the banks evaluate `i XOR right[left[i] XOR key]`. The preparatory pair with key `0xcf` yields `0xaa`. Index `0x8d25` selects slot `0x100e73758` and the return-only leaf at `0x100316938`. The method pair with key `0xf2` yields `0x13`. Index `0x8d54` selects slot `0x100e738d0` and its IOKit import with discriminator `0x21c3`.

## Instruction route

The frame reserves 6,640 B below the register save. It sets two buffer pointers 3,096 B apart and initializes the output count to 3,096 B. With initial table index `0x6a8e`, the entry dispatch reaches two one-byte clearing loops. The first clears 3,096 B at X20 and the second clears 3,096 B at X21. Both finish at the branch on context +0x28 B. For a null value, the tested path writes status at context +0x30 B and unwinds the original frame. For a nonnull value, the tested path writes the object pointer at input +0 B, installs the two method banks and enters `0x100654a48`.

At `0x100654a48` the continuation uses X15 for a byte read. The inspected predecessor initializes X15 to zero, so that modeled route stops at the load at `0x100654a5c`. The preparatory bank stores at `0x100654a94` and the selector 18 call are established by their original instructions and table equations. A continuous trace through those sites still requires the reaching X15 and dispatch state for a compatible route.

## Reproduction

Set `LSKDD_IMAGE` to the unmodified fat executable. With Python, Capstone and Apple `dyld_info` available, run:

```sh
python3 triage_evidence/audit_live_lskdd_selector18_binding.py "$LSKDD_IMAGE"
```

The audit checks 39 instruction sites, 13 fixups and all 512 byte inputs across two equations. It checks the clearing loop arithmetic and retains the seven projected edges. The exploratory offline instruction run used a synthetic context selecting index `0x6a8e` with null and nonnull values at context +0x28 B. The static audit reproduces the source checks and byte equations. The loop's trace uses O(n) time for n initialized bytes and constant working space outside the replay image and trace.

[Auditor](triage_evidence/audit_live_lskdd_selector18_binding.py) [Compressed receipt](triage_evidence/live_lskdd_selector18_binding_audit.json.zst)

## Cross-layer boundary

The loaded connection word at `0x100584c9c` is read through the pointer at SP+0x40. The predecessor stores this pointer at `0x100654a4c` after loading an indexed rebase through the image pool. The original method table maps selector 18 to `ProcessEncryptedData` for a FairPlayIOKit connection. With the initial capacity and ordinary inline transfer, the projected request and full success reply are 3,180 B and 3,148 B. Their Mach IDs are 2865 and 2965. The framework emits at `0x184ebe090` with the connection as COPY_SEND destination and the local reply port as MAKE_SEND_ONCE. The native connection name and transaction remain unknown. [Current method map](live_kext_selector26_report.md) [Mach transport](live_iokit_mach_transport_report.md)

| ID | Assumption and dependent result | Falsification check |
| --- | --- | --- |
| L18.1 | The UUID and SHA-256 pin the installed image. All addresses depend on the pinned arm64e slice. | Recheck the slice hash, original instruction words and chained fixups. |
| L18.2 | The initial index selects the two buffer clearing loops. The fixture proves the selected local route and count writes. | Inspect the caller's context state and replay from that state without injecting an outcome. |
| L18.3 | The four bank cells and X28 survive to the selector block. The call bindings depend on those reaching values. | Establish a continuous route with the reaching X15 definition and check every intervening writer. |
| L18.4 | The connection word names the FairPlayIOKit user client and the initial capacity reaches the method. These premises qualify the Mach envelope. | Match a normal observed request at the framework emission site to its connection, selector and reply. |

High impact for identifying both byte-bank pairs and their conditional callees. Medium impact for the original frame's buffer initialization and null-object continuation.
