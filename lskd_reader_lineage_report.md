# Named-wrapper lineage into the SecureTime reader

The named wrapper `_Vt05NUgPD3Xy28y1R3R` supplies source phase `0x6e3` to internal entry `0xfffffe000a561344`. Its entry and a later flag-decoder continuation supply the frame banks that resolve the reader's acquisition, named query, release and comparison calls. The working context byte at `+0x174` supplies the reader's saved control value; the selected clock arm requires that byte to equal 1. These are source-template correspondences with explicit frame, access and returning-call premises. A complete native operation or daemon request is **unknown**. [RL1-RL8]

The [evidence](triage_evidence/lskd_reader_lineage_checks.json.zst), [extractor](triage_evidence/recover_lskd_reader_lineage.py) and [publication audit](triage_evidence/verify_lskd_reader_lineage_publication.py) retain 24 spans, 1,331 instructions and 5,324 B. Twenty-six UNSAT queries cover 191 lifted instruction instances. Fifteen byte-bank identities cover 3,840 inputs; 33 distinct original pointer slots are retained separately. Two SAT controls document an odd-record counterexample and the absence of a theorem for the unmodeled context transform. The broad interface investigation remains active.

```text
named outer A50E618: partial record R, phase 6e3, original X0 at R+30
  -> bridge A570CF4: forwards R
  -> inner A561344: saves phase, banks and original context key
       -> captured tag/vector lookup and context transform [not fully lifted]
       -> SP+118 -> SP+1f8 = working context
       -> byte[context+174] -> flag record -> decoder A52F730
            !=1 -> index155 -> A5237A8
             =1 -> index13e -> A526D80
                     SecureTime absent -> index71a -> A5237A8
                     SecureTime present -> index737 -> A517624
                          saved CONTROL=1; acquire -> sysctl -> update -> release
                          -> comparison decoder A52F458
```

Hexadecimal constants and address suffixes appear in the diagram. The middle lookup/transform path is captured source, not a whole-path SMT certificate or an observed transaction. [RL2-RL7]

## Provenance and assumptions

Original KC SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized FairPlay image SHA-256 is `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Every retained code byte is compared between these inputs. Exact original nlist matches identify the outer wrapper and `_kernel_sysctlbyname`; no exact name is found for the inner entry. Supplied C lines 18425-18448 and 84475-84496 corroborate the outer and inner source structures. Original A64 establishes widths and register effects. The three original supplied inputs remain unchanged. No new native execution, IDA access or IDB mutation occurs. [RL1]

| ID | Assumption / bound | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| RL1 | Pinned original and normalized inputs describe this build | Addresses, bytes, names, pointers and banks | Recompute hashes, compare original bytes and chained fixups; compare a live image separately |
| RL2 | AArch64 stack alignment, matched body SP/FP and valid record storage | Even outer record, phase join, frame offsets | Vary symbolic aligned placement; odd-address SAT control rejects unrestricted key equality; check actual caller frame |
| RL3 | The retained fragments belong to the same selected source-template execution | Reaching saved phase and bank bindings | Check predecessor choices, actual frame identity and intervening writes; retained route arithmetic is not entirely lifted |
| RL4 | Calls return, preserve the required callee-saved registers and do not overwrite relevant frame cells | Cross-call bank/control joins and conditional bridge displacement | Recover callee effects and aliases; match call/return epochs; no return or noninterference theorem is implied |
| RL5 | Context-transform accesses are valid and disjoint from the live control frame | Context-result publication and route preservation | Lift the pointer codec and pointed writes; establish allocation bounds and nonaliasing; raw vector-slot identity remains unknown |
| RL6 | Flag/seed and SecureTime pointer values belong to the prior selected reader epoch | Selected offsets and clock/update composition | Establish the prior flag=255 premise, seed/pointer stability and native lock lifetime; source roots alone do not establish values |
| RL7 | Fixed-width scalar lifts model the retained instructions; concrete bank bytes and original slots are authoritative | Arithmetic certificates and local target identities | Replay saved SMT, rebuild captures, test signedness/writeback and original-chain membership; PAC execution is separate |
| RL8 | Text census covers its stated immediate-SP store grammar only | Candidate writer inventory | Retain undecoded words; inspect indexed, aliasing and callee writes independently; do not identify logical frames from compiler envelopes |

## Named outer record, phase and inner frame

The original call at `0xfffffe000a50e860` selects bridge `0xfffffe000a570cf4` through slot `0xfffffe00084713c0`, diversity `0x9d3a`. Bridge call `0xfffffe000a570ee4` selects inner entry `0xfffffe000a561344` through slot `0xfffffe0008471610`, diversity `0x1322`. The bridge source forwards original X0=R. The prior [legacy-stack analysis](legacy_stack_report.md) modeled the inner target; this increment inspects its original source without converting those modeled cases into native evidence. [RL1-RL4]

Outer body SP is outer-entry SP minus `0x90`; R=bodySP+`0x18`=entrySP-`0x78`. Thus R is even (indeed 8 modulo 16) for aligned entry SP. For p=low32(R), all operations below are u32:

```text
t = ((p OR 976412f0) XOR fffffffe) - (689bed0f OR NOT32(p))
Kout32 = (t XOR d83db235) * 4ca11177
Kentry64 = u64((R XOR 4bb20883b0a65f3a) * 4ca11177)
```

| Outer record offset (hex) | Width (B) | Written value |
| --- | ---: | --- |
| `00` | 4 | Kout32+W7 |
| `04` | 4 | Kout32 XOR `6e3` |
| `08` | 4 | W4-Kout32 |
| `10` | 8 | X3 |
| `18` | 4 | Kout32 XOR W6 |
| `20` | 8 | X5 |
| `28` | 8 | X2 |
| `30` | 8 | Original outer X0 |
| `38` | 4 | Output; no outer producer write |
| `3c` | 4 | W1-Kout32 |

The initialized union is 52 B within a 64 B envelope. The key join `Kout32=low32(Kentry64)` is proved for even R. It is false for some odd R, as the retained SAT counterexample shows. Consequently the actual aligned outer layout decodes selector S=`0x6e3`; the selector claim is not an unrestricted address identity. [RL2,RL7]

Inner source saves R at SP`+110`, Kentry64 at SP`+e8` and decoded S at SP`+1f4` (store `0xfffffe000a5615e8`). It saves original outer X0 at SP`+a8`. Entry partition is `S XOR (original_X0!=0 ? 0x1e0 : 0)`: nonzero selects index `0x703`/target `0xfffffe000a592994`, zero selects `0x6e3`/target `0xfffffe000a54d474`, both diversity `0x8c42`. This does not establish the original X0's public type. [RL2-RL3,RL7]

The inner prologue reserves 128 B for saved registers and 720 B of locals, totaling 848 B (`0x350`). BodySP=inner-entry SP-`0x350`, FP=inner-entry SP-`0x10`; private reader record FP-`0xb0` equals bodySP+`0x290` (656 B) and is 16 B aligned. At `0xfffffe000a561458..a561464`, the entry advances `*X1` by 64 B. The bridge supplies seed-64 B, so the entry restores seed. The bridge's subsequent displacement would be zero **if this cursor value remains preserved until its returning read**. Later preservation and whole-operation completion remain unknown. [RL2-RL4]

## Frame banks and external call identities

Entry source `0xfffffe000a5615a4..a5615f8` writes these roots. All table offsets in this section are hexadecimal; each pointer is 8 B. [RL1-RL4,RL7]

| Body-SP offset | Source value |
| --- | --- |
| `100 / 108` | `fffffe0007920c10 / fffffe00079170c0` |
| `130 / 128` | `fffffe00079172c0 / fffffe0007919cb0` |
| `190` | `fffffe00079174c0` |
| `1d8 / 1b0` | Controllers `fffffe000ccc2c80 / fffffe000ccc2c60` |
| `198 / 1a0` | Seed cell `fffffe000ccc78b8` / flag cell `fffffe000ccc78e0` |

After the flag call, `0xfffffe000a529094..a5290c4` installs SP`+140/+138`=`fffffe00079171c0/fffffe0007919bb0` and SP`+188/+180`=`fffffe0007920d10/fffffe00079173c0`. Original slots `0xfffffe0008471bd0`, `0xfffffe0008471ce0`, `0xfffffe00084719d8` and `0xfffffe0008471d10` retain these roots before the source's respective small subtractive biases. This resolves the prior comparison helper's three-candidate ambiguity on this matched template. [RL3-RL4,RL7]

For each rule, all 256 byte inputs satisfy `x XOR right[left[x] XOR key]=constant`. TABLE=`0xfffffe000846c420`, POOL=`0xfffffe00084716e0`; index=additive+constant, slot=base+8*index. Original slot metadata establishes the target separately from the normalized qword. [RL1,RL7]

| Reader call PC | Saved banks | Key / additive / constant | Index / original slot | Target / diversity |
| --- | --- | --- | --- | --- |
| `fffffe000a517710` | SP`+130/+128` | `27 / 94d / 61` | `9ae / fffffe0008471190` | `fffffe000a54e220 / 560f` |
| `fffffe000a5177d0` | SP`+100/+108` | `20 / 9a7 / 76` | `a1d / fffffe0008471508` | `fffffe000a508d74 / 6e7d` |
| `fffffe000a5244b8` | SP`+140/+138` | `58 / 984 / 8b` | `a0f / fffffe0008471498` | `fffffe000a551f38 / 84cc` |
| `fffffe000a5246ac` | SP`+188/+180` | `2f / 9fe / 37` | `a35 / fffffe00084715c8` | `fffffe000a52f458 / 2971` |

The first and third targets are the established acquisition/release record adapters; the fourth is the [comparison decoder](lskd_context_compare_report.md). The second is a BTI/branch wrapper to `0xfffffe000a69f3b4`; that stub loads original import slot `0xfffffe000847c508`, target `0xfffffe000c2de71c`, exact aliases `_kernel_sysctlbyname` and `_sysctlbyname`. These are local target identities, not a native authentication or lock-balance result. The query's prior recovered name is `kern.monotonicclock`, with a four-byte output and an eight-byte size cell. Unchecked return status and possibly unchanged prezeroed output remain relevant. [RL3-RL7; reader and SecureTime reports]

The other eleven exhaustive rules resolve TABLE, both controllers, tag table `0xfffffe000ccc7b08`, seed/flag/vector/time cells, earlier acquisition/release adapters and the flag decoder. Every rule's two 256 B banks, bias, original chained slot and normalized target are retained in the evidence; only the four downstream reader bindings are tabulated here.

## Working context and the complete flag-decoder ABI

The captured positive lookup path checks the vector cell `0xfffffe000ccc78d0`, indexes the tag table with `context_key32 & 0x3ff`, rechecks tags around adapter calls, and loads a vector slot. The entire arithmetic/control composition of these captured fragments is **not** lifted. In particular, no accepted context or race-free lookup is asserted. [RL3-RL6]

`0xfffffe000a5315b0..a531914` contains a pointer/data transform. Its source loops include 63 qword-swap iterations (counter 1 through 63) and 32 iterations of 16 B data operations (offsets 0 through 496 B), spanning a 512 B region. These are inspected source loop bounds; pointer validity, data meaning and transform equivalence are unproved. A 140-instruction register audit for `a5316c0..a5318f0` finds no writes to W8/X8 or W9/X9. The only explicit direct SP stores in the full transform affect temporaries `+220..+22f`, result `+118` and status `+14c`. Indirect writes still require RL5; the audit is not a general memory noninterference theorem.

The suffix `a5318f0..a5318f8` copies the transformed qword from SP`+228` to SP`+118`; `a50fa68..a50fa70` copies SP`+118` to SP`+1f8`. Both copies are lifted. Whether this working pointer numerically equals the raw vector slot is unknown. The second SAT control merely shows that an absent transform relation cannot establish equality; it is not a differing-pointer execution of the codec. [RL3-RL5,RL7]

`0xfffffe000a528f98` loads the working context, and `a528f9c` reads its byte at `+174` (372 B) into W19. The comparison path later reads an eight-byte word at `+178` (376 B): these accesses require a minimum 384 B context extent. The previous typed 512 B element is a compatible extent, not yet a proved identity with the transformed working object. [RL3-RL6]

Flag leaf `0xfffffe000a52f730..a52f7d0` has 40 instructions: BTI, 38 completely lifted scalar instructions and RET, with no external call. It returns X0=R and writes only four bytes at R`+00`, PC `0xfffffe000a52f7c8`. Define K=`u64((R XOR b5172dc7dfb9786f)*e1d88903)`, k=low32(K). [RL2,RL7]

| Record offset | Width (B) | Decoded role |
| --- | ---: | --- |
| `08` | 8 | L=record08 XOR K |
| `10` | 8 | Q=record10 XOR K |
| `18` | 4 | mode=u32(record18-k) |
| `1c` | 4 | mask=record1c XOR k |
| `24` | 4 | false_payload=u32(record24-k) |
| `28` | 4 | true_payload=u32(record28+k) |
| `00` | 4 | output=mask XOR selected payload |

```text
predicate = (mode & 1) ? unsigned(L)>unsigned(Q) : L==Q
u32[R] = mask XOR (predicate ? true_payload : false_payload)
```

The selected producer initializes 36 B in a 44 B record envelope: R`+08`=zero_extend(field174) XOR K, R`+10`=K XOR 1, R`+18`=k, R`+1c`=k XOR `ad228785`, R`+20`=k+`b2fd5954`, R`+24`=k+`ad2286d0`, R`+28`=`ad2286bb`-k. R`+20` is not consumed by this decoder; output R`+00` and gap R`+04` are not producer-initialized. Thus L=field174, Q=1, mode=0. The output is `0x13e` for field174=1 and `0x155` otherwise, both positive signed indices. Slots TABLE+8*index point to `0xfffffe000a526d80` and `0xfffffe000a5237a8`, diversity `0x51e4`. [RL2-RL4,RL7]

The time-presence source uses preindexed `LDR X9,[X13,#-4]!`, updating X13 from `0xfffffe000ccc78c4` to cell `0xfffffe000ccc78c0`. With S=`0x6e3`, a nonzero pointer selects `0x737` -> reader `0xfffffe000a517624`; zero selects `0x71a` -> `0xfffffe000a5237a8`, diversity `0x30e7`. The lift includes writeback. Field174 remains in callee-saved X19; reader PC `0xfffffe000a517628` writes its zero-extended value to SP`+1e8`. On this selected entry, CONTROL=1. [RL3-RL4,RL6-RL7]

The [prior comparison composition](lskd_context_compare_report.md) therefore reduces from `unsigned(U)<unsigned(LIMIT) AND low8(CONTROL)==1` to `unsigned(U)<unsigned(LIMIT)` under the matched entry, bank and epoch premises; LIMIT=`u64(context178+ab53c9aeec0afc05)`. This is a continuation predicate. Expiry, admission, external status, successful clock sampling and daemon transport remain unknown. [RL3-RL7]

## Census, validation and bounded continuation questions

The extractor decodes every aligned four-byte word in the 1,688,356 B FairPlay `__TEXT_EXEC`: 422,089 words, 422,038 decoded and 51 retained undecodable words. Its 62-store inventory includes explicit immediate-SP STR/STUR/STRB/STURB/STRH/STURH/STP/STNP stores overlapping the complete eight-byte SP`+1e8`, four-byte SP`+1f4` and eight-byte SP`+1f8` cells. Physical compiler start/end metadata is retained with `reaching_frame_identity_proven=false`. Stores in other frames are not competing definitions until their SP epoch is established; indexed stores, alias writes and callee effects are outside this grammar. [RL8]

The 26 new UNSAT queries, two SAT controls, exhaustive bank checks and prior reader/comparison certificates are replayed by the publication audit. Rebuilding the generator compares original bytes and source structures; replaying serialized queries alone would not independently validate the lifter. Input loading/hash/index work N, retained instructions I, text words W and bank rules R require O(N+I+W+256R) extraction time/space; scalar expression construction is O(I). SMT cost is solver dependent. No physical time unit or precision is assigned to the four-byte clock value in this increment.

| Impact | Bounded next question | Evidence needed |
| --- | --- | --- |
| High | Does the transformed pointer identify the indexed 512 B allocation? | Lift pointer codec, indirect write ranges and data transform with valid/nonaliasing extents |
| High | Is this named wrapper reached from the recovered daemon/IOKit request path? | Recover actual caller, argument provenance and complete return/output route |
| High | Do saved phase, bank roots and context survive the full lookup epoch? | Certify captured route arithmetic, all intervening writes and callee effects |
| High | Do initialization and reader use the same live flag/seed/time and lock epoch? | Match source lifecycle and native state without inferring values from addresses |
| Medium | What supplies context byte174 and word178? | Recover typed initialization, subsequent writers and request-dependent changes |
| Medium | Does the entry cursor remain seed through return? | Complete inner cursor-write and return analysis before deriving an actual zero displacement |
| Low | Do omitted store forms change the saved-cell candidate inventory? | Expand the stated grammar and classify undecoded words without conflating frames |

**QG1** passes: factual binary/interface analysis. **QG2** passes: RL1-RL8 give dependencies and falsification probes. **QG3** passes for this report: named wrapper, frame origins, four reader targets, control producer and transform boundary are covered; full goal remains incomplete. **QG4** passes: byte extents, fixed widths, modular arithmetic, alignment and complexity are explicit. **QG5** passes: odd-address failure, unlifted route/transform, aliasing, call preservation and unsuccessful-query possibilities remain bounded. **QG6** passes: original bytes, nlist, chained slots, supplied C and solver certificates are distinguished. **QG7** passes: impact-ranked continuation questions are recorded.


The [paired context representation](lskd_context_codec_report.md) now proves pointer recovery and the inverse 512 B data transform for matched seed/slot/object epochs. The decoded initializer has byte `+0x174`=0, byte `+0x175`=1 and a zero normalized comparison limit. Later field writers, representation restoration, native epoch matching and daemon request lineage remain open; earlier codec-unknown statements describe the earlier bounded increment.


The [context re-encoding and record-return analysis](lskd_context_return_report.md) now closes the selected default/rejection representation path, decodes original W1 values 1,2,4,5 and state144 updates, and maps private statuses to exact stored u32 results through a cached RW release. Actual operation meanings, matched lock ownership, whole-operation cursor preservation and daemon request lineage remain open. Earlier restoration/selector-unknown statements describe the earlier bounded increment.
