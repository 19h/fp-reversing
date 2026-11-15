# fairplayd: alternative allocation and address-masked zero fill

The b=0 constructor prefix at `0x1008c0750` allocates the buffer whose saved pointer is later copied to U+0. After a separate 48 B object allocation, mode 0 selects an address-dependent byte initializer instead of the mode-1 random-emitter request. Each initialized byte equals the cached-word mask already recovered in the alternative readers. Under the same mask/cache epoch, removing that per-byte mask yields zero. This establishes a source-level zero-fill operation in the alternative representation; the subsequent header follow-up establishes header and U-publication source contracts; native admission remains unknown. No alternative execution, native allocation, Mach message or daemon-kext transaction is added. [AF1-AF6; AF-A1-AF-A7]

| Evidence | Primary provenance and scope |
| --- | --- |
| AF1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. AF4 retains 342 instruction words across 13 spans, 14 authenticated dispatch words and the shared allocator import word. |
| AF2 | [Storage selector](daemon_storage_flag_report.md), [state-container construction](daemon_state_container_construction_report.md) and [allocation cascade](daemon_state_allocation_cascade_report.md). Frozen upstream checks/audits qualify the existing conditional snapshots and call ABI premises. |
| AF3 | [Alternative halfword](daemon_record_storage_report.md) and [alternative word](daemon_alternate_word_report.md) reader contracts. The word checks/audit are pinned in AF4; the shared indexed-mask equation is freshly compared with the writer. |
| AF4 | [Extractor](triage_evidence/recover_daemon_alternative_fill.py), [checks](triage_evidence/daemon_alternative_fill_checks.json.zst): source spans, original fixups, 512 exhaustive bank rows and 76 retained clear-route snapshots. |
| AF5 | [Auditor](triage_evidence/audit_daemon_alternative_fill.py), [receipt](triage_evidence/daemon_alternative_fill_audit.json.zst): 21 nonvacuous UNSAT obligations, three checked normalizer cuts, ten scalar controls and 152 independent zero-store replay visits. |
| AF6 | [Publication verifier](triage_evidence/verify_daemon_alternative_fill_publication.py): fresh extraction/audit, canonical SMT comparison, source/report assertions, manifest delta, original-input preservation and decoded path hygiene. |

## Allocation, saved pointers and mode transfer

Widths are u8/u32/u64; integer arithmetic wraps at its stated width. Pointer arithmetic is u64, and extents/offsets use B. W22 holds encoded extent E. Both the allocation argument and later fill count reduce to N=u32(E+`0x89271594`). For the retained clear-route snapshots E=`0x76d8ea81`, hence N=`0x15`=21 B. This is an arithmetic comparison with existing clear snapshots, not an alternative allocation observation. The constructor's earlier stores zero both outer-SP+0x2338 and +0x3e00. [AF1-AF5; AF-A1-AF-A3]

| Source site | Transfer or request | Recovered role |
| --- | --- | --- |
| `0x10083c8f0`, `0x10083c8f4` | Store u64 zero at outer-SP+0x2338 and +0x3e00 | Initialize the two distinct saved backing-pointer cells |
| `0x1008c07d4` | `BLRAA X8,X17`, X0=ZeroExt32(N), X17=`0x6aa4` | Alternative backing allocation through `libSystem/_malloc` |
| `0x1008c07d8`-`0x1008c07ec` | Save result to X21 and SP+0x2338; W20=0; reload companion from SP+0x3e00 | Alternative pointer and mode-0 handoff |
| `0x100934300`-`0x100934310` | Save result to SP+0x3e00; reload X21 from SP+0x2338; W20=1 | Clear pointer and mode-1 handoff |
| `0x100934a30`-`0x100934a44` | Test X21 OR X0 | Proceed if either backing pointer is nonzero |
| `0x1008a1038` | Same authenticated malloc slot, X0=48 B | U-object allocation request |
| `0x1008a103c`-`0x1008a1060` | Save arbitrary result at SP+0x76e0; select NULL/non-NULL route | Object-allocation result split |
| `0x10092fb3c`-`0x10092fb78` | Mode 0 -> fill setup; mode 1 -> existing emitter-request setup | Representation-dependent initializer selection |

The allocator dispatch uses byte banks at `0x101031da0` and `0x100e99900`. Exhaustive checks establish `x XOR right[left[x] XOR 0x0a] = 0xea` and the corresponding key `0x86` result `0x58`, for every u8 x. Additives `0xcb23` and `0xcbb5` both produce index `0xcc0d`, slot `0x10109ff58`, original word `8c000000a46a08c0`, import `libSystem/_malloc`, logical IA diversity `0x6aa4`, address diversity 0. Source obligations verify the actual lookup addresses and arbitrary u32 controller arithmetic that reaches those banks. Hardware authentication is unmeasured. [AF1, AF4-AF5; AF-A1-AF-A3]

The shared pointer gate tests both values. It reduces to a new-result NULL test only if the companion is known zero. The original zero stores and retained snapshots support that premise at the checked points; arbitrary later companion mutation is excluded. Likewise, the 48 B NULL-result route is identified here, but its complete cleanup behavior is inherited from AF2 rather than re-established for a newly executed alternative case. Ordinary AArch64 call preservation of X19-X28, SP and private saved cells is needed between each pre-call and post-call source contract. No concrete allocator result is admitted in this increment. [AF2, AF4-AF5; AF-A2-AF-A3]

```
selector b=0
  -> malloc(N) -> saved SP+2338 -> future U+0
  -> shared pointer gate -> malloc(48) -> saved SP+76e0
  -> mode 0 -> address-masked byte fill
  -> saved continuation 0x1007d39f0 -> later header work unknown

selector b=1
  -> existing clear allocation -> saved SP+3e00 -> future U+8
  -> shared pointer gate -> malloc(48)
  -> mode 1 -> existing random-emitter request at 0x10093c934
```

The previously proved U-field copy at `0x100825884`-`0x100825890` gives the saved SP+0x2338 value a future U+0 role. The current work does not prove that the alternative fill reaches that later copy or that the new buffer survives all subsequent work. AF2's eventual flag mapping remains conditional: b=0 gives U+0x28=`0xd299e646`, mask4 set, if publication is reached with the selector intact. [AF2-AF5; AF-A3,AF-A6]

## Count reduction, byte transform and loop induction

Fill setup at `0x10087ce80` converts N to u64 counter limit L=`0xb4016435`+ZeroExt32(N). Its mixed Boolean/arithmetic expression is proved equal to that sum for every N32. L is below 2^33, so it cannot wrap u64. N=0 skips the loop through `0x1007f39ac`; positive N enters `0x1006f67d4`. Both routes preserve the saved continuation `0x1007d39f0` in outer-SP+0x92a0. [AF1, AF4-AF5; AF-A2-AF-A4]

Let A be the current output-byte address, M the loaded u32 global mask, T the loaded u64 table pointer and K the loaded cached u64. The original loop at `0x1004e8b28` implements:

```
J = SignExt32(u32((low32(A) & 0xfffffff8) + 0x1cecdea8) & M)
K = load64(T + J)
x = A & ~u64(7)
y = K
for j = 0..7:
    x = (ROR64(x,8) + y) XOR key[j]
    if j < 7: y = x XOR ROR64(y,61)
mask_byte = low8(LSR64(x, 8*(A & 7)))
store8(A,mask_byte)                    # source site 0x1004e8c20
```

| Round j | key[j] / u64 |
| --- | --- |
| 0 | `0x473c853ae26b7ab8` |
| 1 | `0x8f0490db2637da4e` |
| 2 | `0x639ff74d03d39428` |
| 3 | `0xa34408d6869aa02f` |
| 4 | `0x0a23823d71e7a74e` |
| 5 | `0x6c2f97ea7411e380` |
| 6 | `0x3d107423d6820c5f` |
| 7 | `0x71ef41f1f2e87b90` |

The loop loads M through `0x1010c67d4` at `0x1004e8b54`, T through `0x1010c8268` at `0x1004e8b5c`, and K from T+J at `0x1004e8b60`. These are the same global cells, index equation and eight-round keys as the alternative readers. Three universal normalizer lemmas reduce obfuscated XOR rounds 1, 3 and 6; their read-before-write constants are checked against the complete source initializer before the three cuts are applied. The target instructions, image and retained journals are unchanged. [AF1, AF3-AF5; AF-A1,AF-A4-AF-A5]

For iteration i with 0<=i<N, the source induction state is:

| State | Before iteration i | After its byte store and increments |
| --- | --- | --- |
| X21 and X26 | base+ZeroExt32(i) | base+ZeroExt32(i)+1 |
| X11 | 8*(base+ZeroExt32(i)), modulo 2^64 | 8*(base+ZeroExt32(i)+1), modulo 2^64 |
| X12 | `0xb4016435`+i+1 | `0xb4016435`+i+2 |
| X13 | i+1 | i+2 |
| X9 | L | L |
| W8 / W10 / W25 | 0 / `0x4870` / 13 decimal | Unchanged |

The guard X13>`0xffffffff4bfe9bca` is false over this admitted i/N range. The remaining test is i+1<N. The source uses decimal 13 (`0x0d`) as its dispatch XOR delta: repeat index `0x4870`, final index `0x487d`. Confusing it with hexadecimal `0x13` selects an unrelated table entry. At the final iteration the output pointers advance to base+N, and the completion bridge reloads the originally saved continuation. The N=0 route performs no loop-body read or byte store. These source equations and induction establish exactly N byte writes under uninterrupted valid memory and dispatch premises; they are not a loop execution witness. [AF4-AF5; AF-A2-AF-A5]

With M=255, J is aligned to 8 B and lies in [0,248] B, so each 8 B cached-word read lies within a 256 B table. This is a conditional bound; the actual alternative-path M, table allocation, initialization and native publication epoch are unknown. Arbitrary M does not establish a 256 B bound. Output bytes must remain disjoint from the mask/table cells, cached table, dispatch words and saved frame fields. [AF3-AF5; AF-A4-AF-A5]

For the same byte address and unchanged cached-mask inputs, the reader's intermediate decoded byte is `raw_byte XOR mask_byte = 0`. This does not assert that every reader's final logical scalar is zero: the alternative word helper subsequently XORs its assembled u32 with `0x8b3dc651`. Nor does this initializer by itself establish a valid record header. Later field writers beginning after continuation `0x1007d39f0` may replace bytes; those header writes and constructor completion remain the next boundary. [AF2-AF5; AF-A4-AF-A7]

## Authenticated control transfers and retained checks

| Index32 | Target | IA modifier |
| --- | --- | --- |
| `0x4d13` | `0x100934a2c` | `0x62b1` |
| `0x76bf` | `0x10068ae70` | `0x6d79` |
| `0x76d3` | `0x1008a0fa0` | `0x6d79` |
| `0x6802` | `0x1008f01f8` | `0x6d40` |
| `0x6819` | `0x10092fb3c` | `0x6d40` |
| `0x5fc1` | `0x10087ce80` | `0xec47` |
| `0x5fd8` | `0x10093c934` | `0xec47` |
| `0x12b1` | `0x1007d39f0` | `0x6094` |
| `0xa0f6` | `0x1006f67d4` | `0xe8b9` |
| `0xc68d` | `0x1007f39ac` | `0xe8b9` |
| `0x1e73` | `0x1004e8b28` | `0xc336` |
| `0x4870` | `0x1004e8b28` | `0x6d4e` |
| `0x487d` | `0x1006e5c2c` | `0x6d4e` |
| `0xbe45` | `0x1007f39ac` | `0xddd5` |

The original fixup decoder independently checks all 14 slots and the allocator slot. The first loop entry and repeat entry resolve to the same instruction with different IA diversities; these are separate pointer words. The saved bridge changes X17 to `0x6094` before its final branch through X12. [AF1, AF4-AF5]

All 76 retained source constructors are clear-route cases. Nine saved u64 fields per case, 684 values total, verify the two zero pointers, controller pointers, immutable bank pointers, dispatch base and mask/table pointer cells at the existing pending 21 B allocation boundary. These snapshots do not provide an alternative allocator result or an alternative cache epoch. Independent replay of the earlier two zero stores checks 152 instruction visits and writes, 7,296 GP/SP values, 7,296 unchanged Q values and 228 NZCV frames across 76 slices. No complete upstream admission is rerun. [AF2, AF4-AF5; AF-A1-AF-A3]

Ten scalar controls cover a NULL new pointer with nonzero companion, changed reader-mask epoch, unbounded arbitrary M, the decimal dispatch delta and N/i boundaries at 0, 1, 21 and 2^32-1. They are scalar interpretation checks, not serialized target inputs or native admissions. This increment establishes no additional Mach send/receive, port allocation/right transfer, IOKit call or port-emission site. The alternative storage's relation to an external request, on-disk record or kext buffer remains unknown. [AF4-AF5; AF-A6-AF-A7]

## Assumption register and bounded continuation

| Assumption / dependent results | Premise | Stress test or falsification probe |
| --- | --- | --- |
| AF-A1: build-specific source | Pinned image, fixups and upstream receipts | Reject source-word, bank-byte, dispatch-word or receipt-hash changes; do not transfer mappings to another build. |
| AF-A2: source phase and call ABI | Established phase constants; ordinary preservation of X19-X28, SP and private saved cells across the two malloc calls | Source queries quantify controller words, extents and returned pointers; retained replay verifies earlier zero stores. Native callee effects and phase continuity remain unobserved. |
| AF-A3: conditional saved-cell custody | Existing clear snapshots and earlier zero stores; no intervening overwrite before relevant reloads | Check all 684 snapshot values and both independent zero-store effects. Nonzero-companion control demonstrates why the general gate is an OR; do not infer an executed b=0 return. |
| AF-A4: readable stable cache epoch | Valid M/T/K reads, valid writable output and dispatch, disjoint frame/table/output storage; same per-address mask inputs at later decode | Prove source load/store addresses and M=255 bounds; changed-mask control shows the zero-decoding conclusion fails if its mask differs. Actual native cache initialization and synchronization are unknown. |
| AF-A5: loop and normalizer composition | Full u32 extent, admitted 0<=i<N, original initializer constants and valid continuation words | Prove base, step, final branch and all constant contexts; include zero, one and maximum count boundaries. Reject hexadecimal-13 substitution. Memory readability and native termination are not established by arithmetic alone. |
| AF-A6: publication boundary | Saved SP+0x2338 is the input of the previously proved U+0 copy | Recover later header writers and continuous alternative completion before asserting a published usable U or eventual externally visible result. |
| AF-A7: external interpretation | Source-local byte initialization and reader equations only | Match caller/cache epochs and paired daemon-kext bytes before assigning a wire schema, public flag meaning or native interaction. Final word XOR means zero intermediate bytes do not imply zero logical scalar. |

| Impact | Next discriminating work | Information gained |
| --- | --- | --- |
| High | Follow `0x1007d39f0` through the later header writers and U publication | Initial alternative header values, overwrite extent and completed buffer lifetime |
| High | Establish alternative mask/table initialization and publication epoch | Whether the reader/writer zero-decoding and 256 B cache-bound premises hold natively |
| High | Trace saved pointer/tag producers to matching caller epochs | Actual native admission of mode 0 and restrictions on N |
| Medium | Join completed object contracts to paired daemon-kext request/response bytes | Whether this storage representation crosses the recovered external interfaces |
| Low | Check other uses of the same fill loop and saved bridge | Reuse beyond the recovered constructor prefix without conflating phase words |

## Quality gates and reproduction

**QG1** passes: factual source, ABI and data/control-flow analysis. **QG2** passes: AF-A1-AF-A7 identify dependent results and falsification probes. **QG3** passes for this increment: allocation requests, saved bases, mode split, count reduction, byte transform, induction, dispatch and retained zero stores are covered; the broader investigation remains active. **QG4** passes: B extents, u32/u64 narrowing, signed J extension, count bounds and decimal/hexadecimal delta are explicit. **QG5** passes: pointer OR, zero-length bypass, same-epoch condition, final word XOR and incomplete header/publication boundary are distinguished. **QG6** passes: original bytes/fixups, frozen source admissions, fresh solver obligations and independent zero-store replay provide primary provenance. **QG7** passes: impact-labeled extensions are listed.

Run the extractor, auditor and publication verifier with the evidence directory on the Python module path and the existing Capstone/Z3 dependencies. Extraction costs O(parent receipt bytes + retained state bytes + source words + bank rows) time/space; selected replay costs O(visits*32); symbolic construction costs O(source DAG), with solver search separately limited to 30 s/query. The target loop takes O(N) time and O(1) auxiliary state, plus its N B output and externally supplied cache. No native timing or allocation-size feasibility is inferred. All 21 source queries are nonvacuous UNSAT; all ten scalar controls match. Three universal lemmas justify three source-proof cuts with checked contexts; there are zero target instruction rewrites, new target intervals, guest input bytes, owner/root definitions or API-return premises. No native target operation, allocation/free, hardware PAC test or IDB mutation occurs. Original references suffice for this increment; the three original primary inputs remain byte-identical.

## Alternative header publication and immediate caller

The [alternative-header follow-up](daemon_alternative_header_report.md) establishes the three masked header-word writes, U initialization, parent-pointer store and saved return after the alternative fill. Its generic decoded words are 20, u32(X+0xeceb3944) and 1; the remaining eight record bytes retain the fill result under the same cache epoch. The earlier clear caller's source literal X=0x867a282a maps to ASCII `sean`, without proving native alternative use of that literal. U+0x20 is zero, U+0x28 has mask4 set, and published capacity/default match the allocation/header coordinate. Thirty-six source queries, 60 checked normalizer applications, 456 independent producer/store replay visits and a 1,524-instruction source composition qualify the result. Separate caller contracts reload the child/result pair and identify 0x100762e48 as the next boundary. Native caller/cache epochs, J+0x68 publication and daemon-kext pairing remain unknown; no new port emission is established and the full goal remains active.
