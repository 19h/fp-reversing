# Current FairPlay constructor callers and RPC mode selection

All three direct callers of _fcHfFIGhsx in the installed kernel collection put 1 in W4 before entering the constructor. The text-pager interface reaches one of these methods through provider vtable offset 0x8d8. Its origin field travels separately from the mode. For the established dispatcher inputs, mode 1 selects host slot 17 and RPC 502. The alternate mode remains implemented as slot 34 and RPC 700. A current producer of that alternate mode remains unknown. [Previous text-pager and scalar ABI](text_pager_interface_report.md) [Current Mach emission sites](live_fairplay_kernel_rpc_report.md)

## Constructor ingress

| Exact provider method | Vptr offset | Entry PC | Constructor transfer | Origin / mode |
| --- | --- | --- | --- | --- |
| DCkic | 0x880 | 0xfffffe000a545f4c | Tail branch at 0xfffffe000a545f68 | 0 / 1 |
| xhU6d1 | 0x8d0 | 0xfffffe000a546074 | Call at 0xfffffe000a5460a8 | 0 / 1 |
| ycJai39mD8 | 0x8d8 | 0xfffffe000a5460b8 | Call at 0xfffffe000a5460e8 | Copies incoming origin from W4 into W3 / 1 |

Here vptr denotes the provider vtable symbol plus 16 B. Each member resolves through an original authenticated chained pointer. The direct scan walks 15,564,800 aligned words across the collection's two executable segments and finds the three immediate B/BL transfers above to constructor entry 0xfffffe000a6ab970. The scan of 1,037,060 original chained fixups finds zero exact constructor-entry pointers and one exact dispatcher-entry pointer. Computed transfers, interior-entry targets and calls from other images remain outside the constructor-entry census.

In com.apple.IOTextEncryptionFamily, the exact AppleFairplayTextCrypterSession::fairplayOpen entry is 0xfffffe000b174298. It loads the two signed CPU words from session +0x28 and +0x2c into X2/X3 and reads origin from session +0x30 into W4. The authenticated virtual call at 0xfffffe000b17435c loads vptr +0x8d8 and uses modifier discriminator 0x89c4, matching the current provider member. Under that receiver type, ycJai39mD8 forwards the origin as W3 and sets mode as W4. Origin 2 on that path still leaves mode 1. [Earlier hook and origin evidence](text_pager_interface_report.md)

    fairplayOpen -> provider vptr +0x8d8 -> ycJai39mD8
                                             |
                                             v
                            origin W3, mode W4=1
                                             |
                                             v
                       constructor record +0x20 / +0x24
                                             |
                                             v
                            slot lookup and RPC selection

## Record and dispatch flow

The current constructor spills the two u32 arguments at 0xfffffe000a6ab998 and stores them into the record at SP+0x60/0x64 at 0xfffffe000a6abc28. The record starts at SP+0x40. The constructor places its address at generic frame +0x28 and enters the common dispatcher at 0xfffffe000a6478b8. The dispatcher saves the record address at FP-0xe0. The original bank bytes reduce the constructor call index to 0xefa + 0x2d = 0xf27 for all 256 byte inputs. The chained word at index 0xf27 resolves to the dispatcher and has discriminator 0xd0c8, matching the call.

| Consumer | Current instruction sites | Under the retained predecessor values |
| --- | --- | --- |
| Host slot | mode load 0xfffffe000a64bd4c, slot selection 0xfffffe000a64bda4 | W22=0x448 yields W26=1. Mode 1 selects slot 17, and the other equality outcome selects 34. |
| RPC branch | origin and mode load 0xfffffe000a64c97c, authenticated branch 0xfffffe000a64c9ac | W11=0x8ea makes mode 1 select index 0x906 and RPC 502. The other equality outcome selects index 0x8ea and RPC 700. |
| Final request emission | RPC 502 wrapper call 0xfffffe000a5e3288, RPC 700 wrapper call 0xfffffe000a5e34f8 | Both continue to the common send PC 0xfffffe000bd3da9c when the caller and transport prerequisites hold. |

The constructor and dispatcher have the same compiler extents and ordinals as their pinned counterparts. The current constructor is 1,232 B and the dispatcher is 65,848 B. Of 16,770 aligned words across the pair, 16,670 are identical, and the remaining 100 differ only in ADRP, ADD or LDR immediate fields. Across 25 earlier private model cases, 40,925 recorded instruction visits lie within these two extents. All 15 distinct internal authenticated edge identities in those cases, visited 350 times in total, have a unique index with matching authenticated metadata and translated target in both collections. The audit compares the original pinned traces and current source tables. The traces rely on modeled kernel APIs and initialization. No current CPU execution or live PAC, right acquisition or RPC delivery follows from the comparison. [Pinned constructor replay and prerequisites](kext_constructor_request_report.md)

## Assumptions and scope

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| The two collection UUID pairs and digests select the intended images. | Source PCs, preferred vptr and file-backed bindings. | Rehash the collections and compare both embedded UUIDs with the reported running identities. |
| The text-pager receiver has the nominal FairPlayIOKit provider vptr. | The virtual transfer enters ycJai39mD8 and supplies mode 1. | Observe the receiver type and authenticated target on an ordinary pager session. |
| The dispatcher preserves the identified record pointer and follows the retained predecessor values. | Mode 1 selects 17/502, all other u32 modes select 34/700. | Correlate current record address, W22 and W11 at the chosen blocks. |
| Earlier model cases delimit the internal edge audit. | Fifteen current edge correspondences. | Compare current run events and external callee/data bindings for a matched request. |

The audit checks exact symbol and fixup provenance, whole-function extents, immediate-field changes, branch indices, the 32-bit record layout, and replay scope. It takes O(B + F + N + J) time across collection bytes B, fixups F, symbols N, and retained trace events J, with corresponding working space for the source maps and trace. The high-impact result is that none of the confirmed constructor-entry producers can supply alternate mode. Identifying a native alternate producer, the live slot 34 port and the receiver of RPC 700 remains open. [Audit script](triage_evidence/audit_live_fairplay_constructor_mode.py) [Compressed receipt](triage_evidence/live_fairplay_constructor_mode_audit.json.zst)
