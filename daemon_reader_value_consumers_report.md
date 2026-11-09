# Reader value consumers, shared context decisions and variant output staging

Four reader paths converge into two value cells and one context-controlled decision. N20/N21 stage an encoded u32 at frame+0x7390; N22/N23 stage another at+0x78f0. A byte at context+0x68 selects which saved value is compared with context+0x70 or+0x74. N19 separately joins u32, recognized64 and span paths, copies variant caches into a common field envelope, and has a zero-word/span path that writes a saved context pointer through a borrowed output pointer while staging raw success.

These are source-local data/control contracts. Context meaning, native initialization/ownership, complete ordinary publication and daemon-kext pairing remain unknown. The full investigation remains active. No target execution/emulation, FairPlay request or IDB mutation was performed. Original-file references suffice; no additional IDA query was used.

## Provenance and finite coverage

Primary source: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Addresses are unslid source virtual addresses. Constants, offsets and selectors below are hexadecimal unless marked as decimal counts or byte units.

- [Source, writer census, original fixups and references](triage_evidence/daemon_reader_value_consumers_source.json), [recovery script](triage_evidence/recover_daemon_reader_value_consumers.py).
- [Static validator and complete SMT queries](triage_evidence/validate_daemon_reader_value_consumers.py), [proof results](triage_evidence/daemon_reader_value_consumers_checks.json).
- [Preservation seal](triage_evidence/daemon_reader_value_consumers_delivery.json), [scoped quality gates](triage_evidence/daemon_reader_value_consumers_quality_gates.json), [independent publication auditor](triage_evidence/verify_daemon_reader_value_consumers_publication.py).
- Prior [typed reader interfaces](daemon_reader_typed_dispatch_report.md), [normalized extents](daemon_reader_extent_families_report.md), [word/tag codec](daemon_existing_scalar_reader_report.md), [constructor inputs](daemon_constructor_inputs_report.md).

Sixteen source blocks contain1200 instructions /4800 B. Six N19 span-context blocks contribute118 instructions /472 B, and preparation contributes386 instructions /1544 B:1704 captured instruction instances /6816 B. All nonbranch instructions in this set are translated:1681 distinct PCs,1801 instances and1698 SSA definitions. Shared caller blocks are translated separately with each incoming register state. The28-instruction constructor entry is additionally byte-recaptured as a prior-proof reference and is excluded from these new translation counts.

Twenty-five original pointer records support26 branch-slot/modifier matches, including the preceding-word return slot. All16 main blocks have one terminal BRAA, no preceding control transfer and no SP write. Full source checks cover the885-instruction recognized64 helper: it has no store and preserves its loaded X8 return pointer. Original chained-fixup records are independently checked against retained dyld_info evidence; hardware PAC success is not proved.

## Returned u32 staging and persistent-tag rechecks

Let V be the decoded u32 payload word and R=V XOR0x8b3dc651 its established reader representation. Gate/caller roles below inherit the prior word codec's register/key preconditions. Low32 of the phase cell is0x6cf4; the upper32 is arbitrary. E is the saved encoded end value from the earlier extent gate. The recheck uses the persistent u16 tag, rather than the newer working u32 tag cache.

| Family | Word-return block | Store R at frame+ | Copy E to frame+ | Persistent tag cell | Matching tag0xd0ee -> caller | Other tag -> frontier |
|---|---|---|---|---|---|---|
| N19 | 0x100532b34 | 0x7df0 | Later common join+0xdb8 | Later common join+0x958a | 0x1004730ec | Same common join |
| N20 | 0x1005705f4 | 0x26c4 | 0x6f18 | 0x8f7e | 0x1004d5adc | 0x1005f1648 |
| N21 | 0x10052c2bc | 0x6d14 | 0x4828 | 0x8f6e | 0x1004d5adc | 0x1005d0cb0 |
| N22 | 0x100509164 | 0x1744 | 0x8d98 | 0x8f56 | 0x1007f43b4 | 0x1005f1648 |
| N23 | 0x10047c454 | 0x1a60 | 0x3d58 | 0x8f46 | 0x1007f43b4 | 0x100555418 |

N20/N21 also supply X8=&their staged R and W9=0x51e2. N22/N23 supply X9=&their staged R and W8=0x5f85. These are inherited caller-state values, not the core phase substituted at every later block. The queries compose them from the actual return instructions. E and R are stored before selecting the recheck branch. Final external status and complete cleanup on the other-tag frontiers remain outside this increment.

## Two values and one flag-selected comparison

Block0x1007f43b4 consumes either N22 or N23's staged R, stores it at frame+0x78f0, loads a pointer from frame+0x7d98 and stores that pointer at+0x21b0. It stages W6=0x74c29d88. A NULL pointer selects slot0x5f85 ->0x1005f1648; non-NULL selects0x5f87 ->0x1005708f8. Pointer ownership and later traversal remain unknown.

Block0x1004d5adc consumes either N20 or N21's staged R and stores it at frame+0x7390. It loads CTX from frame+0x5e50 and reads u8[CTX+0x68]. This byte selects:

| Flag condition | Source comparison block | Compared u32 values | Equal slot -> frontier | Unequal slot -> frontier |
|---|---|---|---|---|
| Flag=0 | 0x100540018 | [frame+0x7390] == [CTX+0x70] | 0x9790 ->0x1005c34b4 | 0x2fc8 ->0x1005f1648 |
| Flag!=0 | 0x1005fa760 | [frame+0x78f0] == [CTX+0x74] | 0xcb5d ->0x1005b8480 | 0x6959 ->0x1005f1648 |

Both comparison blocks stage W6=0x74c29ccb. The tests compare raw u32 representations. No identifier, credential, version or policy meaning is assigned to the context words without their producer. The nonzero-flag comparison consumes the second saved value, not necessarily the value most recently supplied by N20/N21.

```text
N22 or N23 -> encoded value at78f0 --+--> comparison with CTX+74 (flag!=0)
                                  |
N20 or N21 -> encoded value at7390 ----> comparison with CTX+70 (flag=0)
                         CTX = frame[5e50], flag = u8[CTX+68]
```

This links the four scalar readers through explicit saved cells and conditional consumers. It does not prove that all paths execute sequentially in a native invocation, or that a native request controls CTX or the expected values.

## N19 preceding-word producer and common conditional join

A bounded whole-text local SP-affine scan found one4 B writer candidate for frame+0x9584: STR W4 at0x1005cf730. Its source block0x1005cf720 is the original word decoder's return slot0xaf, IA diversity0x232d. It stores raw W4, then supplies W16=0x1fa, X1=0x79b09650c3f6825c, X4=&frame[0x4120] and X22=&frame[0xa610], selecting slot0x1f39 -> tag decoder0x1005122cc. This is consistent with a preceding header-word role and the established N19 tag-return route. The preceding word's byte-offset producer and semantic identifier role remain unproved.

The census covers3712490 aligned text words, tracks local SP/MOV/ADD/SUB chains and resets conservatively at original targets/control/clobbers. Memory-derived aliases, unsupported stores, opaque callees and frame-epoch equality remain outside its scope. One candidate is not an exhaustive-writer or same-active-frame reaching-definition claim.

Common join0x1004730ec copies u64 frame+0x9590 to+0xdb8, then reads raw preceding word H from+0x9584, persistent tag T from+0x958a and CTX from+0x6368. Its CMP/CCMP sequence selects:

```text
special = (H == 0x8b3dc651) AND (T == 0x1742)
special -> slot7042 ->1007f6f54
other   -> slot70a6 ->10056deb8
```

CCMP uses condition EQ and fallback NZCV=0, whose Z bit is clear. Thus both equalities are required. Under the prior word representation, H=0x8b3dc651 corresponds to a decoded zero word. This block does not additionally test saved length at+0x958c. Protocol meaning of the zero-word/span combination remains unknown.

The u32 and recognized64 returns restore W9=0x6cf4 before the join. Separate corollaries prove that stable saved tags0xd0ee /0xc31c select the ordinary arm. The earlier N19 span chain is freshly recomposed and proves the same incoming W9 phase, rather than assuming a register value at that join.

## Ordinary field envelope and special pointer output

Ordinary block0x10056deb8 copies the following fields:

| Destination frame+ | Width / B | Value |
|---|---:|---|
| 0x8760 | 8 | CTX |
| 0xa618 | 4 | Raw preceding word H |
| 0xa61e | 2 | Persistent tag T |
| 0xa620 | 4 | Raw saved extent from+0x958c |
| 0xa624 | 4 | Raw u32 cache from+0x7df0 |
| 0xa628 | 8 | Raw64 cache from+0x12c8 |
| 0x57a0 | 8 | Span pointer cache from+0x63a0 |

The five fields at+0xa618 through+0xa62f write22 B within a24 B envelope; offsets+4/+5 of that envelope are not written here. Their relative positions0/6/8/12/16 match the prior constructor's leading field positions at+0xa658. The source reference supports structural correspondence, not a complete shared object declaration or size. CTX and the span pointer are staged separately.

All three variant caches are copied regardless of active tag. A SAT source counterexample shows that the raw64 field is still copied with active u32 tag. This is a local store-effect result; native initialization, observability and any external exposure remain unknown. A semantic model that retains only the active value must distinguish that abstraction from the full source memory effects.

The ordinary block selects slot0xb913 ->0x10085e850 for NULL CTX and0xb8e4 ->0x1005bea60 for non-NULL CTX. Further ordinary validation/publication remains unresolved.

The special arm stages raw success0x8b3dc651 at frame+0x2b1c, then enters0x10058816c. That block loads OUT from frame+0x8398, writes CTX as8 B through OUT, restores X21 from+0x7910, supplies X6=0x8b3dc651 and selects slot0x7613 ->0x1005b95e8. This proves a borrowed-pointer publication contract under valid/disjoint owner and stable-frame premises. The actual OUT owner, CTX type, final native return and any relation to a Mach port are unknown.

## Recognized64 helper footprint and result staging

The full885-instruction body at0x100588cb0 loads its return pointer from TABLE[0x8c4], preserves it in X8 to BRAA with IA diversity0xfcf2, dereferences its supplied buffer-pointer cell and reads exactly eight individual bytes at BUF+O+10 through BUF+O+17 modulo2^64. It performs no store. O is the raw cursor supplied in X0; all eight address equalities are proved across the full body.

The returned X9 is stored as raw64 at frame+0x12c8 by0x1004cdeac before joining0x1004730ec. Its complete address-dependent transform and decoded numeric representation remain unproved. The byte-read footprint and continuation ABI do not substitute for that algorithmic recovery. Native backing extent, allocation and lifetime remain unknown.

## Assumption register and falsification probes

| ID | Assumption / boundary | Dependent result | Stress test / falsification probe |
|---|---|---|---|
| VC1 | The pinned original daemon is the intended build. | All addresses, bytes and fixups. | Rehash image and every range; another build invalidates address reuse. |
| VC2 | Frame/cache loads have the named values in the relevant epoch. | Source-composed caller and context joins. | Resolve producers, SP epochs and intervening aliases; numeric offsets alone do not prove this. |
| VC3 | Prior codec register/key preconditions and raw word representations apply. | Decoded-word interpretation and u32 encoding R. | Recheck exact source dependencies and carried registers; the recognized64 transform remains unknown. |
| VC4 | Phase low32=0x6cf4 and raw persistent tags are stable where corollaries require it. | Fixed routes and stable-tag ordinary arms. | Vary phase/tag values; general recheck queries retain arbitrary persistent tag inputs. |
| VC5 | CTX/HEAD/borrowed reads are valid and represent the named fields. | Context flag, expected-word tests and local staging. | Recover pointer producers and owners; no external-control or identity meaning is inferred. |
| VC6 | OUT is valid and does not clobber subsequent frame reads; no unmodeled concurrent write intervenes. | Special borrowed-pointer output/continuation. | Establish owner separation and complete caller lifetime; native aliasing/ordering is not proved. |
| VC7 | Original fixups describe intended authenticated destinations. | Conditional branch/return map. | Independently decode target/key/diversity; hardware PAC/native peer identity remain separate. |
| VC8 | The writer census is a bounded alias subset; field envelope resemblance is not complete type equivalence. | Preceding-word producer candidate and constructor correspondence. | Extend alias/epoch analysis and downstream consumers before promoting either interpretation. |

## Verification and bounded continuation

Twenty-two UNSAT queries cover five payload staging/rechecks, four shared caller contracts, four flag-selected comparison compositions, the preceding-word producer, eight-byte footprint/result staging, the common conditional compare, two stable scalar-tag corollaries, ordinary cache copies, special pointer publication and the span join phase. One SAT query rejects erasing inactive variant-cache stores. Six changed-ledger controls reject a missing helper, changed return branch, invented decoded-u64 claim, wrong writer, missing special output and promoted native owner. These controls check evidence integrity, not native behavior.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_reader_value_consumers.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_reader_value_consumers.py
```

The one-target census costs O(text words); extraction/SSA costs O(captured instructions+pointer records), with O(text bytes+entry resets+captured evidence+SSA) memory. Query construction repeats finite source projections. QF_BV worst-case solver time is not claimed polynomial. Per-query timeout is15 s, subprocess limit20 s; unknown/timeouts are rejected. Publication checking costs O(total artifact bytes+links), with O(manifest+largest JSON) memory. Byte widths, signed/unsigned representations and modulo2^64 arithmetic are explicit; no new nonwrapping/native admission premise is proved.

- High: recover CTX at frame+0x5e50, its flag/expected words and the HEAD producer at+0x7d98 to establish environmental versus request-derived control.
- High: follow the equal branches0x1005c34b4 /0x1005b8480 and N19 ordinary validation0x1005bea60 through final result publication and operation selection.
- High: recover the eight-byte value transform and join the preceding word's actual read offset; footprint and decoder sequencing alone do not establish complete value/identifier semantics.
- Medium: establish ordinary and special OUT lifetimes/alias separation, inactive-cache initialization and complete return/cleanup behavior.
- Medium: compare the constructor and reader field envelopes through consumers before assigning a common record type or full object size.
- Low: retain source-local labels for these flattened continuations until complete compiler-function semantics are known; no IDB names are changed.

No new Mach endpoint or successful daemon-kext exchange is established. Native selector26/RPC502/700 pairing remains unknown.

## Scoped quality gates

QG1: Pass. Technical source observations and falsification probes require no normative conclusion.

QG2: Pass for VC1-VC8. Assumptions, dependencies and tests are explicit.

QG3: Pass for the stated value-consumer/conditional-output increment. Complete transforms, ordinary publication and the cross-layer goal remain active.

QG4: Pass. Byte extents,32/64-bit representations, conditional flags, modular arithmetic and reproducible limits/complexity are explicit.

QG5: Pass for the bounded claims. Context meaning, inactive stores, decoded versus raw64 results, candidate versus reaching definition and structural versus full type correspondence remain distinct.

QG6: Pass. Pinned original bytes, full nonbranch source coverage, independently checked fixups, fresh census and complete solver queries support the local contracts. Prior constructor bytes are recaptured and clearly separate from new translation counts.

QG7: Pass for the finite high/medium/low continuation list. No full-goal completion is claimed.


## Reader allocation-origin refinement

[Reader allocation origins and context admission](daemon_reader_container_origins_report.md): a private caller derives modec4dd and parent+8 output;the original malloc binding requests16 B,initializes a two-u64 pair and publishes it for empty decoded input. N19 scalar/span defaults are identified. Comparison context is incoming X10 saved before a separate112 B allocation;shared value cells and a saved head are initialized. Fourteen ranges/249 instructions,18 fixups/15 slot matches,256 bank inputs,234 translated PCs,15 UNSAT queries,one SAT provenance counterexample and six changed-ledger controls pass. Native owners/upstream modes,complete object types,non-NULL head production and daemon-kext pairing remain unknown.
