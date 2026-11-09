# A 720-byte allocation and a candidate producer of the +0x238 region

Original source at `0x100BAE048` requests 720 bytes through a conditionally resolved `_malloc` import. For incoming phase `0x471C`, a non-NULL return dispatches directly to `0x100B0B6FC`. This initializer clears a 64-byte region at owner+0x238, which contains the offset range requested by the preceding cache path. **The allocated pointer is not yet connected to the registry's entry+8 value.** This is a candidate producer, not a completed ownership or daemon-to-kext join. The full interface investigation remains active. [R1-R10]

The [cache publication report](daemon_cache_publication_report.md) stops before reading 20 bytes at registry-derived R+0x238. That frontier is unchanged. The present increment independently establishes an allocation/initializer contract without assigning bytes or an owner to R. The earlier [872-byte object initialization](daemon_object_initialization_report.md) is a separate allocation-site contract; matching offsets do not identify the objects.

| Registry field | Established consumer access | Minimum required extent | Allocation candidate / unresolved edge |
| --- | --- | --- | --- |
| Entry+8, u64 value | R+0x238, 20-byte request | 588 bytes from R | New 720-byte initializer; publication into this field unknown |
| Entry+0x10, u64 head | Object+0x360, 8-byte link read | 872 bytes from object | Earlier 872-byte construction; publication into this field unknown |

These two field contracts remain distinct. Their allocation-size compatibility does not establish either publication edge or a shared enclosing class.

Primary source is `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Six fresh read-only ranges from IDB target `6b117c693e3b` cover 1,368 bytes and match the image. Original code, bounded censuses and fixups are retained in [source evidence](triage_evidence/daemon_record720_source.json). The [source proofs](triage_evidence/daemon_record720_proofs.json) and [fresh A64 checks](triage_evidence/daemon_record720_checks.json) distinguish universal equations from finite declared executions.

## Allocation, saved pointer and dispatch

At analyst cutpoint `0x100BADFC0`, let Q be incoming W9:u32. The source computes the following values modulo 2^32:

```text
S = (Q + 0x29FB14DB) & 0xD604FF8D
W23 = S
W24 = (Q - 0x71C) | 0x423
W19 = Q + 0xF75

X0 = 720 before the imported call
P = declared malloc return
[SP+0x3118]:u64 = P
index = (Q + 0xF75) XOR (P != 0 ? (S XOR 0x5B86) : 0)
```

Under saved `[SP+0x2978]=0x100FC4230` and incoming X13=`0x101031FA0`, the two byte banks select constant 0x5D for every possible byte input. Adding 0xCBB0 gives index 0xCC0D and original slot `0x10109FF58`, `_malloc`, IA diversity 0x6AA4, address diversity 0. The original chained word/import is independently decoded. These bank roots are premises; their native caller production is unknown. No allocator executes outside the private model.

| Source PC | Established action |
| --- | --- |
| 0x100BADFC0 | Preserve incoming X25 in X26 |
| 0x100BADFC4 | Save incoming X22 at SP+0x26F0 |
| 0x100BADFDC | Preserve the incoming controller pointer from X23 in X11 |
| 0x100BAE02C | Produce W19=Q+0xF75 |
| 0x100BAE040 | Set allocation extent to 720 bytes |
| 0x100BAE048 | Conditional `_malloc` import boundary, IA/0x6AA4 |
| 0x100BAE04C,0x100BAE050 | Restore X16 and dispatch-table X30 from the saved frame |
| 0x100BAE058 | Save the full returned pointer at SP+0x3118 |
| 0x100BAE05C..0x100BAE074 | Compute return-dependent table index and load successor |
| 0x100BAE08C | Authenticated logical transfer, IA/0x1774 |

| Q=0x471C outcome | Index | Original slot | Successor |
| --- | --- | --- | --- |
| P=0 | 0x5691 | 0x101065378 | 0x1009687C8 |
| P!=0 | 0x5692 | 0x101065380 | 0x100B0B6FC |

Both slots have original IA diversity 0x1774 and address diversity 0. Hardware authentication does not execute. The source-equation proof covers arbitrary Q:u32 and P:u64. The selected-phase partition uses Q=0x471C. This phase is not uniquely inferred from the successor: an exhaustive u16 subdomain contains 240 phases selecting the same non-NULL index. The native incoming phase/caller is unknown.

## Partial allocation layout and exact byte definitions

The non-NULL path retains P in X0 and saves it at SP+0x3118 before transferring to the initializer. Source `0x100B0B7A0` and `0x100B0B7A4` reload that same saved pointer into X10 and X25. Under a valid 720-byte allocation disjoint from the frame, all 75 stores through these aliases have the following combined footprint:

| Owner-relative interval, inclusive | Extent | Value / exact source evidence |
| --- | --- | --- |
| +0x000..+0x013 | 20 bytes | Ten zero halfword stores, 0x100B0B7AC..0x100B0B7D0 |
| +0x238..+0x277 | 64 bytes | Thirty zero halfword stores, 0x100B0B7D4..0x100B0B850, then zero u32 at 0x100B0B86C |
| +0x278..+0x2B3 | 60 bytes | Thirty zero halfword stores, 0x100B0B728..0x100B0B79C |
| +0x2B4..+0x2B7 | 4 bytes | Zero u32, 0x100B0B7A8 |
| +0x2BC | 1 byte | Zero byte, 0x100B0B71C |
| +0x2C0..+0x2C7 | 8 bytes | Zero u64, 0x100B0B700 |
| +0x2C8..+0x2CB | 4 bytes | Little-endian u32 0x8B3DC651, 0x100B0B710 |

Thus bytes +0x238..+0x2B7 form one contiguous 128-byte zeroed interval through two adjacent 64-byte regions. The checked stores define 161 bytes; the other 559 bytes remain undefined. The highest accessed end is +0x2CC=716 bytes. The allocation request is 0x2D0=720 bytes, leaving the final four bytes untouched here. The source does not establish a complete C structure, field ownership, hash-buffer role, synchronization semantics or intended representation for the stored constant.

```text
declared phase and bank roots
          |
          v
    malloc request 720 B
          |
          +-- NULL -> separate successor; no initializer stores
          |
          +-- P -> saved SP+0x3118 -> initializer aliases P
                                        |
                                        +-- P+0x238: 64 zeroed bytes

registry entry+8 -> R -> request R+0x238, 20 B
                    ^
                    |
              P-to-R edge unknown
```

The fresh non-NULL checks stop before `0x100B0B87C`, which loads an unavailable saved-frame field at SP+0x2DC0. This preserves the actual evidence boundary after the initializer stores. The NULL checks stop before executing successor `0x1009687C8`. Neither successor is resumed by supplying missing bytes.

## Bounded field census and another consumer candidate

The original aligned text spans 14,849,960 bytes from `0x100001058`. Four independently recaptured literal-encoding censuses yield:

| Syntactic predicate | Matches | Coverage limit |
| --- | --- | --- |
| ADD Xd,Xn/SP,#0x238, unshifted | 34 | Includes local stack-address constructions |
| Unsigned-immediate memory access at +0x238, base register not SP | 29 | Base can still be a stack alias; matching offset does not establish object identity |
| STR Xt,[Xn,#8], base register not SP | 521 | Does not cover paired, unscaled, register-indexed or constructed-address stores |
| STR Xt,[SP,#0x3118] | 2 | Other frame epochs and aliased/paired writers remain possible |

The two literal saved-pointer writers are `0x100BAE058` and `0x10077D3E0`. The latter saves X20+0x50 in a different source context; it is not assigned to this allocation epoch. These searches improve candidate selection, not complete writer recovery.

Another original sequence at `0x100A5A514` loads a record pointer from SP+0x1360, saves its +8 field address, loads that field and adds 0x238 at `0x100A5A524`. W11 becomes 0x10 before a longer register setup and an authenticated transfer at `0x100A5A648`. Its target, ultimate memory direction/extent and relationship to R remain unknown. W11=16 alone does not establish a 16-byte ABI argument. This is a second independently located +8-to-+0x238 use, with no object-identity inference.

## Assumption register

| ID | Premise / dependent result | Stress test / falsification probe |
| --- | --- | --- |
| R1 | Pinned source and IDB match / all addresses | Rehash specimen and text; compare six fresh ranges, original fixup fields and import ordinal/name |
| R2 | Stated bank roots apply / malloc identity | Exhaust all 256 byte inputs; retain native root/caller production as unknown |
| R3 | Q=0x471C at the allocation cutpoint / selected successors | Prove the all-u32 equation and both return cases; enumerate the 240 u16 alternatives to prevent unique-phase inference |
| R4 | Imported malloc returns the declared NULL or private owner / finite source continuation | Verify literal 720 and slot/modifier; vary volatile GPRs/NZCV, four controller pairs and two frame/owner placements |
| R5 | Successful P covers 720 bytes without address wrap and is disjoint from the frame / initializer memory semantics | Explicit unsigned/disjoint symbolic premises; guarded concrete memory effects and exact defined-byte masks |
| R6 | The saved pointer retains its source epoch / alias continuity | Check the actual SP+0x3118 write and both reloads; retain the second literal writer separately |
| R7 | Instruction and API models cover only declared general-register/memory effects / fresh A64 evidence | Reject undefined register/byte reads and outside-owner writes; no native allocator, PAC or imported memory effects execute |
| R8 | +0x238 and +8 matches are syntactic / candidate interpretation | Recapture every aligned text word; record excluded address forms and stack aliases; require actual pointer continuity before joining objects |
| R9 | R remains an unowned scalar in the earlier profiles / preserved foreign frontier | Do not assign the new zeroed bytes to R; require registry publication and field-writer continuity |
| R10 | Partial source recovery does not establish transport / architecture | Require owner/byte flow into an identified Mach/IOKit emission and matching driver consumer |

Allocation/dispatch claims depend on R1-R4 and R7. Initializer composition additionally uses R5-R6. Census/candidate interpretation uses R8-R9. Cross-layer limitations use R10. Native allocation type, caller reachability, pointer lifetime, registry publication, later +0x238 writers and IPC linkage remain unknown.

## Validation, complexity and bounded continuation

Seven rebuilt source obligations and 14 persisted SMT files pass. The lift covers 120 instructions. Fresh private execution covers 64 cases: 32 NULL and 32 non-NULL, two SP placements, two owner placements, four u32 controller pairs and two volatile ABI patterns. The cohort contains 6,400 source visits, including 6,272 ordinary emulated A64 instructions and 128 modeled imported-call/logical-transfer events; 640 ordered reads and 2,528 ordered writes are checked. Undefined initial heap bytes remain undefined even though private physical pages have fill patterns.

The census is O(text words) time and O(matches) output space. Replay is O(cases*instructions) time and O(one mapped case+retained effects) space. Initializer work is fixed at this cutpoint; no whole-routine complexity is assigned. Symbolic lifting is O(lifted instructions) expression construction plus solver resources, with a 30 s per-query limit. Counts/extents are decimal bytes; offsets are hexadecimal; scalar arithmetic has the explicit u32/u64 widths above.

| Impact | Next evidence needed | Consequence |
| --- | --- | --- |
| High | Continuous P publication into registry entry+8 | Would connect an actual allocation to the retained R+0x238 input boundary |
| High | Saved SP+0x2DC0 producer and later stores into P+0x238 | Would distinguish initialized zeros from the eventual consumed record bytes |
| High | Actual native predecessor of the allocation cutpoint | Would replace phase and bank-root premises with caller evidence |
| High | P/R byte flow into a resolved transport call | Would establish a daemon/kext join absent from this increment |
| Medium | Resolve the second +8-to-+0x238 consumer | Would distinguish shared layout from unrelated same-offset use |
| Medium | Complete record fields and ownership transitions | Would establish lifetime/ABI extent beyond the partial initializer |

Reproduce with the pinned Python/Z3 environment used by the preceding reports: run [capture](triage_evidence/capture_daemon_record720.py), [proof producer](triage_evidence/prove_daemon_record720.py), then [independent checks](triage_evidence/validate_daemon_record720.py). Scoped [quality gates](triage_evidence/daemon_record720_quality_gates.json) and [delivery/preservation checks](triage_evidence/daemon_record720_delivery.json) record the final artifact checks.

QG1: factual source/ABI scope. QG2: R1-R10 with falsification probes. QG3: candidate allocation, initializer, aliases and field censuses covered; full goal remains incomplete. QG4: explicit widths, byte extents, modular arithmetic and execution counts. QG5: alias/no-wrap premises, partial initialization, duplicate phase witnesses and unknown native/registry joins are explicit. QG6: original source/fixups, current IDB bytes, rebuilt source equations and fresh A64 effects support scoped claims. QG7: impact-ranked continuation evidence is listed above.
