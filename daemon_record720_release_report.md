# Owner release, input-span reader and a callback with modifier zero

The declared continuation now connects the original 720-byte allocation to a `_free(P)` request through private control **0xBBB3**. A separate route establishes that the leading u64 is used as a byte pointer and the following decoded u32 supplies a reader count. A 64-byte private reader interface admits a byte access under a recovered u32 count/index equation. Selected bounded inputs reach callback `0x10040F7A4` through original slot `0x1010389A8`, using `BLRAAZ` with modifier zero. Registry publication and daemon-to-kext transport linkage remain unknown. [R1-R14]

This extends the [private record/cursor report](daemon_record720_handoff_report.md) and the [720-byte initializer report](daemon_record720_report.md). Their original profiles and stopped frontiers are unchanged. The new cases declare two additional runtime scalars; borrowed byte spans use newly constructed input headers. No bytes are assigned to the old unowned scalar-pointer fixtures. The full interface goal remains active.

Primary image: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. [Original source/banks/fixups](triage_evidence/daemon_record720_release_source.json), [source equations](triage_evidence/daemon_record720_release_proofs.json), [declared cases and ABI snapshots](triage_evidence/daemon_record720_release_profiles.json) and [independent replay checks](triage_evidence/daemon_record720_release_checks.json) retain the evidence. No native allocator, callback, Mach/IOKit operation or hardware PAC executes.

## Allocation release and the second record epoch

Let F be the outer SP, R=F+0xDE90 the reused caller record, and P the successful modeled allocation of720 bytes. The post-status caller emits a different interface from the earlier control0x7A3A record:

```text
Krelease(R) = u32((low32(R) XOR 0xB5DA7AC1) * 0x5DE29BE3)
encoded control = u32(0xBBB3 - Krelease(R))
```

| Second record field | Width | Source-established operation |
| --- | --- | --- |
| R+0 | u32 output | Raw result written at0x100270AC4 |
| R+8 | u64 input | P written at0x100BE0BE8; loaded at0x100435D08 |
| R+0x10 | u32 input | Encoded control written at0x100BE0BF8; decoded at0x100435D00..0x100435D04 |

The minimum accessed span is20 bytes. R+0x10 reuses only the low32 bits of the earlier pointer field; its old upper32 bits are not a new pointer argument. The caller's prekey identity requires an even record address. The actual frame-derived R is16-byte aligned in the declared cases; the decoder's arithmetic identity covers arbitrary u64 address bits.

The call at0x100BE0C50 reaches wrapper0x100435B9C through original slot0x1010A0840, IA diversity0x485B/address diversity0.

The wrapper at0x100435B9C decodes the control by adding Krelease to the raw u32. Under control0xBBB3, a non-NULL P selects original slot0x101097C88 ->0x100260F00, IA diversity0x1611. A NULL P instead selects0x101097DE0 ->0x100270AC4 under the same modifier. The complete all-u32/control, all-u64/pointer equation is retained in the proofs; these are private controls, not IOKit selectors.

| Release step | Source site / slot | Established effect |
| --- | --- | --- |
| Inspect optional subordinate address | 0x100260F18 | Load u64 Q from P+0x2C0 |
| Q=0 | Slot0x10105DCD0 ->0x1001C6088 | Skip subordinate release |
| Q!=0 | Slot0x10105DBC0 ->0x1002084F0 | Select conditional subordinate-release sequence |
| Subordinate free request | 0x10020857C | `_free(Q)`, original slot0x10109FF30, IA0x46A2 |
| After normal subordinate-free return | 0x100208580 | Store NULL at P+0x2C0 |
| Owner free request | 0x1001C6100 | `_free(P)`, same original slot and modifier |
| After normal owner-free return | 0x100270AC4 | Store raw result0x364C5349 at R+0 |

Both Q branches use IA diversity0x4168/address diversity0. The source-local non-NULL-Q contract establishes its free argument and subsequent clear; no native allocation/ownership of Q is inferred. Concrete cases retain Q=0 from the original initializer. They read exactly that eight-byte field before requesting `_free(P)`. They perform no additional P-byte writes and never read the other undefined payload bytes.

The library model retires the private720-byte owner and invalidates all its defined bytes. This is a model of a normal `_free` return, not observed native allocator behavior or secure erasure. All checked release cases reach0x100B90EF4 and stop before reading the unavailable u64 saved field F+0x24F8. No freed P byte is read before that frontier. Caller-volatile GPRs/NZCV are not read after the modeled free before the relevant overwrite in these paths; the two arbitrary void X0 outcomes do not affect this observed result.

## The leading u64 is a byte pointer in this route

The earlier input components produce U:u64 and D:u32 from a declared12-byte input B:

```text
U = BE64(B[0:8]) XOR 0x9898989898989898
D = BE32(B[8:12]) XOR 0x98989898
```

They remain explicit source-component handovers. Native input provenance and intervening caller continuity are unknown. This route now uses U as an address at0x100315AE8. This does not retroactively assign a pointer type to every use of the shared eight-byte packing routine in other phases.

The nested reader's caller record A is derived from its caller FP-0xA8. Its address key is:

```text
Kreader(A) = u32((low32(A) XOR 0xE732D262) * 0xBA209EF7)
```

The caller key identity requires A aligned to8 bytes, satisfied by the source FP relation in these cases. The decoder key identity has no alignment restriction on its u64 arithmetic input.

| Reader record field | Width | Emission / meaning established here |
| --- | --- | --- |
| A+0 | u32 | Encoded control0x80D1-Kreader; store0x1003E5558 |
| A+8 | u64 | Input address U; store0x1003E5578 |
| A+0x18 | u64 | Private scratch/output address; store0x1003E5580 |
| A+0x20 | u64 | Private scratch/output address; store0x1003E5570 |
| A+0x28 | u32 | D+0x67AC8198-Kreader; store0x1003E5594 |
| A+0x30 | u64 | Private scratch/output address; store0x1003E5560 |
| A+0x38 | u64 | Address of encoded u32 index J; store0x1003E5568 |

The highest accessed field ends at A+0x40, requiring64 bytes. The other scratch addresses are not assigned complete native output types. Source0x10044DD40 decodes this count/index interface:

```text
decoded count = u32(raw[A+0x28] + Kreader(A) + 0x98537E68) = D
index I       = u32(load32(pointer[A+0x38]) + 0xAF506591)
admit read    = (u32(I+1) <= D)     // unsigned, modulo2^32 addition
read address  = u64(U + ZeroExt32(I))
```

The caller at0x1003E55F4 reaches reader0x10044DD40 through original slot0x1010A05C0, IA diversity0xB06F/address diversity0.

For I!=0xFFFFFFFF, the admission condition is equivalent to I<D. The modular equation and its nonwrapping corollary are separate source obligations. No full-loop counter invariant, native bounds guarantee or whole-parser memory-safety claim follows from this local predicate.

In the declared cases, I=0 at this gate. Admitted reads select slot0x10107A610 ->0x100315ABC under IA diversity0x8E42; the non-admitted private-control route remains separately captured in the source inventory. Source0x100315ABC loads U from A+8;0x100315AE8 performs LDRB through U+I. The192 retained unowned U fixtures stop before this first byte read.

## First-byte gate, borrowed spans and callback interface

The first-byte source computes, for every b:u8:

```text
encoded byte value = u32((b XOR 0x22) + 0x21E8AE00)
escape predicate   = ((b & 0x1F) == 0x1F)
```

Under the recovered reader phase, the predicate selects private index0xB087 versus0xB048. This is a byte/branch identity. A complete standard format, canonicality rules, extended form or decoder identity is not established.

The borrowed-input cases use new valid owners and fresh12-byte headers encoding their addresses and byte counts. Their six byte strings are `3000`, `3003020101`, `3000020101`, `020101`, `040141` and `1F1F00`. Lengths are2,3 or5 bytes. All observed input reads remain within those declared spans, and no source input byte is written. The three0x30 cases reach the following callback:

| Interface | Source evidence |
| --- | --- |
| Static descriptor base | 0x1010389A0; the leading u32's meaning remains unknown |
| Callback field | Descriptor+8, original chained slot0x1010389A8 |
| Callback target | 0x10040F7A4 |
| Emission site | 0x100478EF4, `BLRAAZ X8` |
| Authentication metadata | IA key, diversity0, address diversity0; hardware PAC not executed |
| Established X0 argument | Source-supplied private-frame address; complete pointee contract unknown |
| Established X1 argument | Address of the callback record below; target0x10040F7C8 preserves it in X20 |

Only these two argument roles are established. The complete callback prototype and callee semantics are unknown. The new executor models BLRAAZ as the source-attested logical call after verifying the original slot, target and zero modifier. An earlier exploratory exception was the old executor's unsupported instruction, not native target behavior.

| Callback record field | Width | Observed value in the three0x30 fixtures |
| --- | --- | --- |
| T+0 | u32 | 0x21E8AE12, matching the first-byte transform of0x30 |
| T+4 | u32 | XOR0x8B3DC651 yields0,3,0 respectively |
| T+8 | u64 | U+2 |
| T+0x10 | u32 | XOR0x8B3DC651 yields2,5,2 respectively |
| T+0x14..+0x17 | 4 bytes | Undefined and unread before the frontier |
| T+0x18 | u64 | U |

The accessed/emitted span is32 bytes, with28 bytes defined. These observations are consistent with a content count and an end offset for the first short element; that interpretation remains finite evidence. The trailing-byte fixture `3000020101` distinguishes the observed end offset2 from the supplied total byte count5. No universal callback-record codec or full native C structure is inferred from these samples.

The callback's initial guard read uses the preceding declared imported-data model. All192 callback cases stop at0x10040F7E0 before u32 runtime word0x1010B7E78. The other bounded prefixes enter the release path. None establishes P publication into registry entry+8 or a Mach/IOKit transaction.

```text
malloc(720) -> initializer -> private control7A3A
                                |
              +-----------------+----------------------+
              |                                        |
        returning status                         U,D reader record
              |                                        |
       private controlBBB3                 +-----------+-----------+
              |                            |                       |
      read P+0x2C0 = NULL           unowned U -> STOP       fresh borrowed span
              |                                                    |
        request free(P)                              +-------------+---------+
              |                                      |                       |
      model retires owner                     selected0x30 inputs       other tested inputs
              |                                      |                       |
     saved F+0x24F8 -> STOP                  callback40F7A4            release path
                                                     |
                                            runtime word -> STOP

P -> registry publication -> driver transport: unknown
```

## Assumption register

| ID | Premise / dependent results | Stress test / falsification probe |
| --- | --- | --- |
| R1 | Pinned image and original fixups / code, data and bindings | Rehash specimen/opcodes; independently decode85 used fixups; compare14 current-IDB ranges |
| R2 | Prior allocation/input components and their value handover apply / new paths | Rebuild36 original106-instruction input components; retain native intervening caller/frame continuity as unknown |
| R3 | The two added runtime words are declared scalars / state-dependent continuation | Test both words zero and both all ones; source-prove their u64 updates; do not assign native initial values or complete writer histories |
| R4 | All new cases use the preceding declared guard/environment model / callback and returning paths | Keep the old missing-guard profiles frozen; verify source guard reads/comparison in the new paths; native guard value remains unknown |
| R5 | Frame,720-byte owner and borrowed spans are valid, disjoint and do not wrap / byte effects | Two SP, allocation and span placements; exact owner/defined-byte guards; no read is allowed from old unowned pointers |
| R6 | Caller address-key identities use their stated alignment premises / record codecs | Release caller requires even R; reader caller requires A&7=0; decoder identities are separately proved for arbitrary u64 address bits |
| R7 | Malloc/free have the modeled scalar ABI and normal return / lifetime composition | Verify arguments, slots, modifiers and preserved GPRs; two void X0/volatile/NZCV outcomes; invalidate720 owner bytes and reject subsequent accesses |
| R8 | Non-NULL subordinate Q is only a source-local conditional contract / optional free | Prove all-u64 branch/argument identities and post-return clear; no native Q ownership or executed non-NULL-child case is inferred |
| R9 | Pointer authentication is logical / call and callback identity | Track actual load/spill origins, original IA metadata and modifier zero; no hardware PAC success is claimed |
| R10 | Reader admission is the explicit modular equation / count and index interpretation | Prove all-u32 predicate and separate nonwrapping corollary; retain missing full-loop/native-owner invariants |
| R11 | Callback-field interpretation is finite / apparent content count and end offset | Check192 emitted records, relocated spans and a trailing-byte fixture; do not infer long forms or a standard decoder identity |
| R12 | Independent replay proves only its stated source domain / validation scope | Replay all768 cases, ordered effects, known GPR snapshots and actual indirect operands; no full native execution or target failure is inferred |
| R13 | IDA normalizes one callback pointer / database provenance | Parse all14 tabular rows with exact byte counts; allow only the known8-byte fixup field to normalize; other bytes must match exactly |
| R14 | Registry publication and transport remain absent from this evidence / goal status | Require an actual P-to-registry store and matching emitted/received data before joining daemon and kext paths |

Whole declared continuations depend on R1-R7 and R9/R12. The subordinate path uses R8. Reader interpretation uses R10; callback interpretation uses R11. IDB coverage uses R13. Cross-layer limits use R14. Native record types, input provenance, caller reachability, resource ownership outside the private models, callback semantics and IPC linkage remain unknown.

## Validation and remaining interfaces

Twenty-two rebuilt source obligations,44 SMT artifacts and255 lifted instructions pass. The768 declared cases comprise384 extensions retaining scalar U fixtures and384 fresh borrowed-span cases. They vary two frame placements, two720-byte owner placements, two preceding runtime-state sets, two new scalar-state variants and two volatile/physical fill patterns. Borrowed spans additionally use two addresses and six byte strings. All allocation returns are declared non-NULL; the older initializer report retains its separate NULL-return partition.

The cohort contains4,157,440 source visits:3,941,312 ordinary emulated A64 instructions,212,864 logical transfers/returns,2,112 modeled PACIBSP heads,768 modeled malloc calls and384 modeled free calls. Independent instruction-at-a-time replay checks all768 cases,490,880 ordered writes,341,056 reads and4,224 ABI snapshots of known registers. It verifies2,561 observed original opcodes and85 used original fixups. Thirty-six fresh input components add3,816 source instruction visits.

| Accepted endpoint | Cases | Evidence boundary |
| --- | --- | --- |
| 0x100B90EF4 | 384 | P retired by the library model; stop before undefined saved u64 F+0x24F8 |
| 0x100315AE8 | 192 | Stop before first byte through unowned U |
| 0x10040F7E0 | 192 | Callback entered; stop before unknown u32 runtime word0x1010B7E78 |

The byte audit checks384 release requests/retired-owner masks/void-call liveness paths,576 reader count guards,4,032 reader-record fields,384 borrowed spans with704 byte reads and960 callback-record fields. The callback records have exactly28 defined bytes in their32-byte span. The old scalar fixtures are never made readable by a borrowed-span case.

The14 IDB ranges cover2,536 bytes. Thirteen instruction ranges match directly; the56-byte static descriptor range matches after normalizing only slot0x1010389A8 from its original chained word to its decoded target. This is explicit database representation handling, not a code patch. All original inputs, previous evidence and IDBs remain unchanged except for the separately listed reporting updates.

Reproduce in the pinned Python/Z3 environment using [source capture](triage_evidence/capture_daemon_record720_release.py), [proof producer](triage_evidence/prove_daemon_record720_release.py), [case producer](triage_evidence/probe_daemon_record720_release.py) and [independent validation](triage_evidence/validate_daemon_record720_release.py). The [continuous executor](triage_evidence/daemon_record720_release_replay.py) and [independent replayer](triage_evidence/replay_daemon_record720_release.py) separately implement malloc/free effects, pointer-origin checks and BLRAAZ handling. [Delivery/preservation checks](triage_evidence/daemon_record720_release_delivery.json) and [scoped quality gates](triage_evidence/daemon_record720_release_quality_gates.json) seal this increment.

Capture/banks require O(source bytes+256*bank rules) time/output. Execution/replay is O(source visits+effects) time and O(largest private map+known-byte state+decoder cache) space; retained compressed profiles add their output size. Source lifting is O(lifted instructions) plus solver resources, with30 s per query. Counts and byte extents are exact. Arithmetic wraps at its stated u32/u64 width. No full-reader termination or whole-native-path complexity is established.

| Impact | Next source evidence | Consequence |
| --- | --- | --- |
| High | Producer/epoch of saved F+0x24F8 | Would extend the owner-release return into its actual caller result |
| High | State0x1010B7E78 and callback0x10040F7A4 record consumers | Would establish the callback's operation and whether it populates another object |
| High | Selection rules for descriptor0x1010389A0 and other callback fields | Would recover the dispatch architecture without treating the descriptor as a native class by assumption |
| High | Actual native caller/input producer for the pointer/count header | Would connect these private ABIs to external control or transport |
| High | P publication into registry entry+8 and later data emission | Would establish the missing daemon/kext ownership/data-flow join |
| Medium | Broader bounded input forms and callback-field codecs | Would test the count/end interpretation before assigning a standard format name |
| Medium | Other writers and interleaving of0x1010B6570/0x1010B9278/0x1010C4670 | Would separate declared scalar premises from actual shared-state lifetime |

QG1: factual source/ABI scope. QG2: R1-R14 list dependent results and falsification probes. QG3: release, count/index input and callback increment covered; full objective remains incomplete. QG4: explicit byte extents, widths, modular arithmetic and execution/event counts. QG5: native versus modeled ownership, aligned keys, wrap conditions, record epochs, bounded callback samples and genuine frontiers remain separate. QG6: original code/fixups, IDB representation checks, rebuilt equations and independent A64/byte/snapshot replay provide scoped provenance. QG7: impact-ranked continuation evidence is retained above.
