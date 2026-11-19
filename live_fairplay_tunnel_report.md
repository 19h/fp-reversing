# Installed FairPlay secure tunnel allocation and insertion

In the macOS build `26C5035r` collection, selected blocks of `_PRnut72j9` request a 120 B `site.FPSecureTunnel` object, initialize it, and pass the same pointer to an occupied-entry writer. The prior cleanup audit issues a matching typed-free request for a saved entry payload. The selected allocation and cleanup descriptor images are byte-identical. Equality of a particular allocated and freed pointer across native invocations remains unknown. The new analysis also resolves an independent 8 B `site.FPSecureTunnelAttr` allocation on the missing-header branch. [Current cleanup](live_fairplay_table_cleanup_report.md)

```text
Selector 26 provider -> _PRnut72j9 entry
                            |
                            ?  entry-to-selected-block reachability
                            |
              typed alloc -> P -> scratch -> table entry +16 B
                                                   |
                                          ?  native object continuity
                                                   |
                                cleanup lookup -> typed free request
```

## Image and interface bindings

The original fileset SHA-256 is `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`. The kernel and kext UUIDs are `90195379-954d-3ca3-baac-327341f14211` and `316464f8-eade-30ca-938e-2f430b1ed5bc`. The installed function container is `[0xfffffe000a676398, 0xfffffe000a6a7ac0)`. The prior provider audit resolves a call to that entry with the staging pointer, extent, and provider context in X0–X2. The selected allocation and table paths below have independent branch-state premises. [Provider transfer](live_kext_selector26_transfer_report.md)

| Selected operation | Installed call site | Slot, IA modifier | Resolved destination |
| --- | --- | --- | --- |
| Tunnel allocation | `0xfffffe000a69b6ec` | `0xfffffe0008491258`, `0xd0c8` | `_IOMallocTypeImpl` at `0xfffffe000c509774` |
| Fallback header allocation | `0xfffffe000a69b858` | `0xfffffe0008491258`, `0xd0c8` | Same allocator with an 8 B descriptor |
| Insertion lookup | `0xfffffe000a69d33c` | `0xfffffe0008491288`, `0x6a0f` | Lookup at `0xfffffe000a5ef4e4` |
| Occupied-entry write | `0xfffffe000a69d4a8` | `0xfffffe00084914a8`, `0x3936` | Writer at `0xfffffe000a5efdb4` |

The tunnel allocator's X0 comes from pool cell `0xfffffe0008488e40`. The code subtracts 4 B from its resolved value to reach the descriptor at `0xfffffe0008492bc0`. The cleanup descriptor resides at `0xfffffe0008492a00`. Each carries the same name, empty signature, flags `0x6c` and extent of 120 B. The fallback pool cell `0xfffffe0008488ab8` similarly supplies descriptor-plus-four for `0xfffffe0008492240`, with name `site.FPSecureTunnelAttr`, empty signature, flags `0x6c` and extent of 8 B. [Current audit receipt](triage_evidence/live_fairplay_tunnel_audit.json.zst)

## Allocation and header selection

Let C denote the routine's scratch base, S the selected source and result record, and P the 120 B allocation result. The routine stores P at C+0x148 before the null test. The selected null path reaches `0xfffffe000a69f64c`. With P and the existing header at C+0x6d0 both nonzero, the code copies six header bytes and enters the initializer at `0xfffffe000a69b958`. It publishes P at C+0x48 and C+0x6e8.

| P byte range | Value after the selected initialization |
| --- | --- |
| `0x00–0x05` | Existing six-byte header |
| `0x06–0x07` | Prior allocation bytes |
| `0x08–0x17` | 16 B from S+0x710 |
| `0x18–0x37` | 32 B from S+0x26 |
| `0x38–0x67` | 48 B of `0xc7` |
| `0x68` | `0x01` |
| `0x69–0x6b` | Prior allocation bytes |
| `0x6c–0x6f`, `0x70–0x73` | Two u32 stores of `0x31ae0066` |
| `0x74–0x77` | u32 from S+0x2b4 |

The initialization writes 115 distinct bytes and leaves 5 prior bytes. The subsequent insertion path replaces the word at P+0x6c. Field meanings beyond the local stores remain unknown. [Allocation and initialization proof](secure_tunnel_allocation_report.md)

With no existing header and the selected dispatcher state, the fallback calls the 8 B allocator. The F bank resolves the call index to `0xf13`, and the V bank resolves the descriptor index to `0x23`. The descriptor pointer is saved at SP+0x848 and loaded into X0 at `0xfffffe000a69b850`. A null return selects branch index `0x798` and lands at `0xfffffe000a69c06c`. A nonzero return Q selects `0x797` and lands at `0xfffffe000a69b8c4`. The code writes u32 7 and u16 0 to Q, saves Q in scratch C+0x3f8, and copies the six initialized bytes to P. The outgoing branch `0x794` lands at `0xfffffe000a6a00e0`. Q's release and this branch's eventual convergence remain unknown.

## Insertion and cleanup correspondence

The selected path transfers P from C+0x48 to C+0x218 and C+0x5d8. It saves the pointer at SP+0x9e0 at `0xfffffe000a69ce9c` and reloads it at `0xfffffe000a69cf90`. The code uses the selected header H through C+0x200 and constructs the lookup record at S+0x968. With raw marker M from S+0x20, the lookup key is `M XOR 0x31ae0066`. The optional found-byte pointer is zero. Status `0x31ae0066` at record +0x18 admits either an available index or an occupied match. Other statuses select `0xfffffe000a69f64c`.

The writer uses the chosen 24 B entry and stores occupied tag `0x629f8777` at +0 B, `0x1ee45f68039f9913 + zero_extend(key32)` at +8 B, and P at +16 B. It preserves bytes +4 B through +7 B. The modular header counter increments only on an empty-to-occupied transition in this arm. On ordinary return, the selected path stores M at S+0xd0 and at +0x6c through P reloaded from C+0x48. For a coherent table of N entries, lookup and the store take O(N) time and O(1) additional state. [Historical insertion record and proofs](secure_tunnel_table_insertion_report.md)

Cleanup derives the same key when its node marker equals M, reads the entry payload, and uses the saved value in its final typed-free gate. The historical UIDList producer connects P+0x6c to node+4 B. Installed-build continuity of that marker transfer, table serialization, and actual pointer identity across insertion and cleanup remain unknown. The new sites pass private kernel pointers and emit no Mach message. Their correlation with a native daemon transaction remains open. [Historical node publication](userclient_uidlist_publication_report.md) [Mach endpoints and emission sites](mach_ports_report.md)

## Assumptions and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| T1 | The current bytes match the identified fileset and prior receipts. Selected proof transfer depends on this. | Rehash the collection, verify its UUIDs and function bounds, and compare every selected instruction word. |
| T2 | The selected state reaches the audited blocks with the recorded bank and scratch roots. Allocator, fallback, and writer resolution depend on it. | Enumerate the bank input bytes, decode each fixup, and close the predecessor and saved-cell def-use chains from the provider entry. |
| T3 | The allocator returns ordinarily and the frame preserves P. Copy and publication depend on these conditions. | Check the null edges and follow all writes to saved cells and their aliases between the pointer stores and reloads. |
| T4 | H, its array extent and the selected index stay coherent through mutation. The 24 B entry write and loop bound depend on it. | Establish capacity and backing extent for the invocation, then identify the synchronization covering lookup and write. |
| T5 | For cross-invocation equality, the cleanup node carries M and the entry retains P. | Verify the installed UIDList write and collect the matched marker, header, index, and payload events for one native lifetime. |

High impact applies to the installed pointer flow between the typed allocation and occupied entry. Medium impact applies to the separate default-header allocation and its unresolved lifetime. Low impact applies to assigning semantic names to the marker or byte patterns from the selected stores.

QG1 covers factual scope. QG2 records premises and probes. QG3 covers allocation, fallback, insertion and the cleanup interface. QG4 checks byte ranges, offsets, and bounded probing. QG5 tracks null paths and unresolved continuity. QG6 uses the original fileset, hash-pinned receipts, and 25 source-proof replays. QG7 bounds the implications for object ownership and daemon IPC. The audit compares 1,189 selected instruction words, resolves the two relocated operands, checks 12 historical branch fixups and one new fallback fixup, and evaluates six bank rules over 256 inputs each. The full function body has a separate identity hash. No native FairPlay transaction was exercised.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_tunnel.py "$CURRENT_COLLECTION"
```
