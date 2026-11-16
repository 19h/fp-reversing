# Kernel allocation, conditional returns and retirement interfaces

The original kernel source closes selected argument and return contracts below the kext's allocation/free calls. A null zone-backend result is preserved through the selected size-allocator return path, and a null size-allocator result is preserved by `_IOMallocData`. Typed allocation return blocks preserve every u64 result. These are conditional return theorems: native backend null outcomes, ordinary return, allocation identity and ownership remain unknown.

This report extends [query failure](userclient_query_failure_report.md), [context lifecycle](userclient_context_lifecycle_report.md), [parser cleanup](userclient_parser_cleanup_report.md), [table reclamation](userclient_hash_table_reclamation_report.md), and [AES carrier initialization](aes_carrier_initialization_report.md). No additional Mach endpoint, port transfer or emission location is established.

## Source and claim register

All newly selected instructions come from the original kernel collection, SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. The normalized kext SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` anchors the predecessor kext contracts. The normalized kext does not contain these kernel function bodies. Original compiler bounds, complete bytes and available exact symbols are captured. No external XNU source revision or additional IDA evidence was needed.

| Claim | Established result | Dependencies |
| --- | --- | --- |
| KA1 | At the selected size-selection cut, sizes0..32 B with flag bit0x100 clear form the exact zone address given below;14 and32 B select adjacent modulo16-bit indexes | KA-A1-A4 |
| KA2 | A returned null zone result reaches null size result; a returned null size result reaches null `_IOMallocData` result; selected typed return blocks preserve arbitrary result64 | KA-A1-A5 |
| KA3 | For a null runtime descriptor-zone field and stable flag/size fields, typed fallback allocation and retirement select the same heap and low24-bit size for every u32 flags/size pair | KA-A1-A4, KA-A6 |
| KA4 | `_IOFreeData` skips its lower call and accounting on a null pointer; its nonnull request forwards the original u64 extent and same data-heap address as `_IOMallocData` | KA-A1-A5 |
| KA5 | Lower size retirement skips its backend on a null value and restores its selected saved frame; typed retirement reads the descriptor before selecting its runtime zone/fallback path | KA-A1-A5, KA-A6 |
| KA6 | Nonnull14/32 B size-retirement requests pass the original pointer, raw discriminator1 and two distinct frame aliases to the exact lower query helper | KA-A1-A5 |
| KA7 | The newly recovered conditional returns connect to the preceding kext failure/status contract under its same frame, helper-return, storage and callback premises | KA-A1-A7; seven predecessor obligations rechecked. Native transaction reachability remains unknown |

```text
kext allocation request
  +-- typed adapter -> typed zone or typed fallback
  +-- data adapter  -> size allocator -> zone backend
                           |
                     returned zero, if any
                           |
                     selected null return
                           |
                  kext saved-error cleanup

kext retirement request
  +-- typed adapter -> descriptor zone or size fallback
  +-- data adapter  -> pointer-null guard -> size retirement
                                             |
                                  small-size query helper
```

## Small-size selection and request ABI

At `0xfffffe000bcfe660`, the size allocator forms `(N+31) AND~31`, tests W2 bit0x100, and selects the original N when that bit is clear. The original14 B data request uses raw flags0x31000 and the typed fallback32 B request uses0xd1004; both have that bit clear. The earlier optional OR0x40 does not change it.

Let b be the selected u16 base index at this block-entry cut. Native preparation may obtain it from heap metadata or substitute a runtime default; that preparation, per-thread statistics, and heap initialization are not executed by this audit. For0<=N<=32 B and bit0x100 clear:

```text
i(N) = (b + [N > 16]) mod 65536
A(N) = 0xfffffe000caeb480 + 192 * i(N)
```

The192 factor is the source stride in B. The computed address does not wrap u64 for any u16 index. This proves address formation, not the native zone-array length, membership, initialized state or valid dereference. In particular, b=65535 makes the32 B index wrap to0.

| Query extent | Selected index | Computed zone address |
| --- | --- | --- |
| 14 B data | b | 0xfffffe000caeb480+192*b |
| 32 B node | (b+1) mod65536 | 0xfffffe000caeb480+192*((b+1) mod65536) |

The selected request at `0xfffffe000bcfe6d8` calls0xfffffe000bd75c64 with X0=the selected zone pointer, X1=the selected statistics pointer and the current flags in W2. The recorded request theorem uses0x31000; runtime preparation of those pointers and any flag augmentation remain separate cuts. This helper has no exact symbol in the captured original symbol tables.

## Conditional result and frame custody

| Original source | Selected behavior | What remains conditional |
| --- | --- | --- |
| `0xfffffe000bcfe6dc..0xfffffe000bcfe6e4` | X2 receives returned X0; zero selects0xfffffe000bcfe79c | Zone-backend return value is supplied by an ordinary-call cut |
| `0xfffffe000bcfe79c..0xfffffe000bcfe7a4` then0xfffffe000bcfe770 | Temporary X0 is replaced by X2 at0xfffffe000bcfe774; zero remains zero | Native backend production of zero is unknown |
| `0xfffffe000bcfe778..0xfffffe000bcfe784` | Restores X19-X22, X29-X30 and the48 B frame before RETAB | Saved frame is intact; native PAC authentication/return is a premise |
| `0xfffffe000c4ba63c` | Null size-allocator result skips accounting and selects0xfffffe000c4ba690 | Lower allocator normally returns the selected result |
| `0xfffffe000c4ba690..0xfffffe000c4ba698` | Restores X19-X20, X29-X30 and32 B frame; X0 remains zero | RETAB envelope is captured, not authenticated |
| `0xfffffe000bcfebe0` and0xfffffe000bcfec24 | Each typed return restores X29-X30 and16 B frame without writing X0 | Arbitrary u64 lower result, including zero, is preserved on ordinary return |

The audit explicitly models STP/LDP pre-index and post-index stack writeback. It starts selected prologues after PACIBSP, treats the already-signed incoming LR as an arbitrary saved word, and checks restoration of that word. Six original RETAB instructions are captured as return envelopes outside the131 modeled instructions. Hardware PAC, stack validity in a native run and nonreturn/panic behavior are not established.

The size-allocator null path skips its nonnull-result pointer transformations and accounting. The data-adapter null path skips its global and optional per-task accounting. The proof establishes the selected control path and frame/result effects; it does not execute the other paths or establish a native allocation failure.

## Typed allocation/free congruence

`_IOFreeTypeImpl` at0xfffffe000c4ba368 is BTI C followed by a direct branch to0xfffffe000bcff010. It passes X0=descriptor and X1=value unchanged. The lower routine reads descriptor+0 before testing that runtime zone field. For nonzero zone, it tail-branches to0xfffffe000bd7a4b8 with the descriptor and value still in X0/X1. The lower target is unnamed in the original symbol capture; its native semantics are outside this audit.

For a zero runtime zone field, the typed allocation and retirement fallback blocks use the following identical heap selection:

| Descriptor condition | Heap argument |
| --- | --- |
| flags bit0x08 set | 0xfffffe0007f8bfb0 |
| bit0x08 clear, bit0x8000 clear | 0xfffffe0007f36938 |
| bit0x08 clear, bit0x8000 set | 0xfffffe0007e6a780 |

Both mask the descriptor's u32 size with0x00ffffff. Allocation places that zero-extended result in X1; retirement places it in X2 and retains the value in X1. Allocation calls0xfffffe000bcfe5b8; retirement tail-branches to0xfffffe000bcfec48. For query-node flags0x64 and size32, both select heap0xfffffe0007f36938 and32 B.

This is congruence of requested heap addresses and extents under equal stable metadata and zero runtime zone fields. It does not establish identical native descriptor instances, a shared runtime zone, valid allocation origin, unique ownership or actual deallocation. The predecessor's allocation and retirement descriptor addresses are distinct despite equal normalized metadata. Their runtime zone fields may change independently. The typed routine still needs a readable descriptor when the supplied value is null, because its descriptor read precedes the lower value-null guard.

## Data retirement and lower query interface

| Boundary | Exact original behavior |
| --- | --- |
| `_IOFreeData` null guard | At0xfffffe000c4ba85c, X0=0 selects0xfffffe000c4ba8c8; no lower call or accounting on this path |
| Nonnull data request | At0xfffffe000c4ba874, calls0xfffffe000bcfec48 with X0=heap0xfffffe0007f8bfb0, X1=original data pointer, X2=original u64 extent |
| Data allocation counterpart | `_IOMallocData` selects the same data heap and forwards its original u64 extent in X1, flags0x31000 and X3=0 |
| Lower size-free null guard | At0xfffffe000bcfec60, X1=0 selects0xfffffe000bcfed58; no lower backend call on that path |
| Lower null return | Restores X19-X22, X29-X30 and64 B frame before the captured RETAB at0xfffffe000bcfed68 |

For nonnull14/32 B values, the source size guard and32768 B split select the small-size query call at `0xfffffe000bcfec9c`. Let F be SP on entry to the lower size-free function. At that call:

| Argument / saved state | Exact value |
| --- | --- |
| Target | 0xfffffe000bd792dc, no exact original symbol |
| X0 | Original value pointer |
| X1 | F-64+8 |
| W2 | Raw discriminator1 |
| X3 | F-64 |
| X20 / X21 | Original heap / original extent |
| Two frame cells before call | u64 zero at F-64 and F-64+8 |

The caller subsequently reads those frame cells and compares a returned span with the supplied extent. This supports the inferred metadata-query role; it does not establish the helper's complete semantics or that it writes either alias. The audit stops at the query request. Its return, zone/offset validation, subsequent pointer transformations, lower free calls and native effects remain open. The large-size retirement path is captured for provenance but not recovered here.

## Evidence, assumptions and validation

[Extractor](triage_evidence/recover_kernel_allocator_boundary.py), [instruction audit](triage_evidence/audit_kernel_allocator_boundary.py), [delivery verifier](triage_evidence/verify_kernel_allocator_boundary_delivery.py), [checks archive](triage_evidence/kernel_allocator_boundary_checks.json.zst), and [audit archive](triage_evidence/kernel_allocator_boundary_audit.json.zst) provide the source and formula receipts.

Decoded checks SHA-256: `3a5cc821c3e6527e0e5058ccaab1a21982d96fd5e8bfa68ccc8518f5f08f3e83`.

Decoded audit SHA-256: `02b90e8e2341842d4c2ae6131d3ff0a38da20481bd3dd649bba8ef64ced91863`.

Eight complete original functions contain340 captured instructions. The model covers27 selected blocks and131 instructions; the remaining captured words are provenance, not a claim of complete allocator recovery. Nineteen new nonvacuous obligations account for291 source-instruction instances and272 linked-edge checks across those obligations. Seven predecessor obligations are re-solved. Altering the final result source register produces a SAT counterexample to the null-result claim.

| Assumption | Dependent claims | Stress test / falsification probe |
| --- | --- | --- |
| KA-A1: Only the pinned original collection and predecessor kext image are covered | KA1-KA7 | Original bytes, compiler bounds, exact symbols, three predecessor kernel-container matches and fresh extraction; recapture for another build |
| KA-A2: Modeled AArch64 u32/u64, CLZ, shifts, conditional selection and pair-load/store writeback semantics apply | KA1-KA7 |19 reconstructed nonvacuous obligations, exact linked-edge checks, full flags/size domains and changed-return-register SAT control |
| KA-A3: Selected descriptor and saved frame storage are valid, nonwrapping and separate; incoming SP is16 B aligned | KA1-KA7 | Exact symbolic cells, frame extents, pre/post-index restoration and interval constraints; native capacity/identity not inferred |
| KA-A4: Selected block-entry cuts, runtime base/statistics preparation and flag conditions apply | KA1-KA3, KA6 | Explicit enter() cuts separate omitted preparation; arbitrary u16 base,0..32 B domain, 16-bit wrap case, arbitrary bit0x100-clear flags, all descriptor flags/size pairs |
| KA-A5: Ordinary native helper returns preserve callee-saved registers, SP and saved frame memory; signed LR and RETAB authentication are valid | KA2, KA4-KA7 | Havoc X0-X18/X30 on modeled call return, check result and saved registers, capture six original RETAB envelopes; backend outcomes/PAC/nonreturn remain unknown |
| KA-A6: Compared typed fallback descriptors have equal stable flags/size and zero runtime zone fields | KA3, KA5, KA7 | Separate descriptor-zone branches, all-bit heap selectors and24-bit size masks; inspect native mutable descriptor identity/zone initialization independently |
| KA-A7: Predecessor query caller/failure phases retain their declared frame/context/status/callback cuts | KA7 | Re-solve original32 B typed request,14 B data request, lower heap/flag arguments and first saved-error cleanup/callback proofs; native daemon transaction pairing and public error status remain unknown |

## Bounded continuation and quality gates

| Impact | Next evidence | Contribution |
| --- | --- | --- |
| High | Exact zone-backend return/nonreturn contract and initialized runtime zones | Determine native outcome domains; conditional null preservation alone does not establish a null allocation |
| High | Small-retirement query helper and its caller's post-query validation/free path | Establish returned metadata, pointer transformations and lower retirement requests |
| High | Runtime descriptor identity, ownership and synchronization across allocation/publication/retirement | Discharge matching-ABI versus actual-lifetime distinctions |
| High | Same-image daemon/provider transaction and public return continuation | Tie internal query/error behavior to external IPC |
| Medium | Runtime heap/base/statistics preparation and alternate large-size paths | Extend the small-block contract to environmental and size-dependent behavior |
| Medium | Native signed-frame/PAC evidence and stable private storage | Discharge ordinary-return and frame-preservation premises |
| Low | Other typed views and ordinary data callers using the same adapters | Identify independently corroborated architectural reuse |

Extraction requires O(B+I+S) time/space for image bytes B, decoded instructions I and scanned symbols S. Formula construction requires O(instruction instances+query DAG); CLZ width is fixed32. SMT search is separate with30 s/query limits. Sizes and strides use B; pointers/results use u64, descriptor fields use u32, and selected indexes use u16. No target code or IPC executes and no IDA database is modified.

- **QG1**: Claims concern factual source, data, control and ABI properties.
- **QG2**: KA-A1-KA-A7 identify assumptions, dependent claims and falsification probes.
- **QG3**: Selected zone address/request, conditional results/frames, typed fallback congruence, data/lower null guards,14/32 B query ABI and predecessor connection are covered. The full interface goal remains active.
- **QG4**: Field widths, 16/32/48/64 B frames,14/32 B requests,192 B stride, modulo16-bit arithmetic, counts and complexity are explicit and reproducible.
- **QG5**: Address formation versus membership, matching metadata versus native identity, helper return cuts versus outcome existence, saved LR restoration versus PAC, and inferred query role versus helper semantics remain distinct.
- **QG6**: Eight original function captures,131 selected modeled instructions,19 nonvacuous obligations, seven predecessor rechecks,272 linked-edge checks and a source-register mutation counterexample support the bounded claims.
- **QG7**: Ranked continuation preserves backend outcomes, metadata validation, native lifetime/locking, daemon transactions, environment preparation and signed-frame evidence as open frontiers.
