# Constructor identifier lookup, replacement and retirement

The constructor finish stage `0x1005ae7a0` performs a first-match identifier lookup. An exact miss appends the newly constructed node; an exact match selects position-preserving replacement and retirement of the old record. These are conditional original-source contracts. The 12 retained private profiles contain 60 constructor lookups, all misses, with 48 candidate comparisons; none observes replacement. Native execution, authenticated call completion and daemon-kext delivery remain unknown. [LK1-LK8]

Evidence: [source, pointer records, banks and frozen episodes](triage_evidence/daemon_constructor_lookup_source.json), [component queries and translations](triage_evidence/daemon_constructor_lookup_checks.json), [extractor](triage_evidence/recover_daemon_constructor_lookup.py), [validator](triage_evidence/validate_daemon_constructor_lookup.py), [preservation](triage_evidence/daemon_constructor_lookup_delivery.json), [scoped gates](triage_evidence/daemon_constructor_lookup_quality_gates.json). The [constructor-input report](daemon_constructor_inputs_report.md), [header codec](daemon_header_codec_report.md), [payload codec](daemon_payload_codec_report.md) and [record-stream report](daemon_record_stream_report.md) supply adjacent contracts. Reference files sufficed; no new IDA access, database mutation, target execution, native API call or emulation occurred.

| Evidence | Verified scope |
| --- | --- |
| Original thin daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Fresh fragments | 29 ranges, 1286 instructions, 5144 B; 34 original pointer records |
| Prior recapture | 28 ranges, 7048 B |
| Static certificate | 48 UNSAT queries: 33 decoder components, 14 structural components, one abstract link-store composition |
| Translation | 1320 instruction instances, 1296 SSA definitions; component reuse is explicit |
| Retirement selectors | Two original byte-bank pairs, 256 inputs each; 512 cases select the original `_free` binding under pinned roots |
| Frozen constructor evidence | 12 profiles, 60 lookup episodes, 48 candidate comparisons, zero matched replacements |
| Other caller | 12 separate lookup episodes, 24 candidate comparisons; all mismatches |
| Altered evidence | Eight alterations rejected; source bytes, observations, counts, branch target, banks and input preservation |

Addresses are unslid original VAs. Offsets and constants are hexadecimal; byte extents are decimal unless prefixed `0x`. u32/u64 arithmetic is modular. These flattened internal interfaces are not recovered public C prototypes. K denotes the shared frame, C the 16 B container, NODE a 32 B node, and BUF its record buffer. [LK1-LK3]

```text
new record complete
        |
        v
lookup first matching identifier
        |
        +-- miss --> append NEW ------------+
        |                                   |
        +-- match -> splice NEW for OLD      |
                     |                      |
                     v                      |
                  free OLD.buf              |
                  free OLD                  |
                     |                      |
                     +----------------------+
                                            v
                                  saved constructor continuation
```

## Lookup interface and status [LK1-LK4]

At `0x1006fd1b8`, X8 supplies C, W9 the encoded identifier HE, X11 the output-cell address, W10 a continuation-table selector and W22 the core phase `0x6cf4`. The constructor supplies selector `0x12fa`, resolving to `0x1008351c8` with IA modifier `0x068f`. The helper saves that resolved continuation at K+`0x7060`, HE/u32 at K+`0xaa5c`, and OUT/u64 at K+`0xaa60`. The constructor had initialized its OUT cell K+`0x80b8` to zero.

| Case | Raw W6 | Output-cell effect | Caller disposition |
| --- | --- | --- | --- |
| C=0 | `0x74c29d88` | Unwritten by lookup | Exact-success gate fails |
| End of chain | `0x74c29ded` | Writes zero/u64 | Exact-miss gate selects append |
| Identifier equality | `0x8b3dc651` | Writes first matched NODE/u64 | Exact-success gate selects replacement |

These are observed source constants, not assigned public error names. `0x100742a30` first tests **signed** `s32(W6)<s32(0x74c29ded)`. `0x10069a114` then requires exact success; `0x1009a0b64` requires exact miss. Other statuses reach the `0x1008c3528` cleanup frontier, whose complete behavior remains unknown.

| Routine/site | Recovered role |
| --- | --- |
| `0x100697188` | Reads NODE=[LINK+0]; LINK starts at C and becomes the previous candidate |
| `0x100914e3c` | Loads BUF=[NODE+0x18], prepares decoder offset zero and continuation selector `0xc8` |
| `0x1006f6bf0` | Decoder preparation; preserves X1/X4/X16 and has no calls; full context-read validity is a premise |
| `0x100800004` | Decodes one four-byte word using the address-dependent mask |
| `0x100615a1c` | Compares decoded W4 with saved HE using exact u32 equality |
| `0x1005bb1b0` | Mismatch continuation; advances through NODE.next |
| `0x100914a10` | Writes candidate or zero to OUT, transfers raw status into W6 |
| `0x1006c5c2c` | Continuation mediator; authenticated transfer through saved X10 |

The search compares only the four-byte identifier representation at buffer offset zero. No type/tag or full-extent validation is established on this path. With a finite stable acyclic chain and readable nodes/buffers, first-match search takes O(k) time and O(1) scalar space for k examined candidates. Termination for cyclic or concurrently modified lists is not established. [LK2-LK4]

## Word decoder and constructor representation [LK1-LK4]

The decoder takes X1=BUF and X4=`0x661a590b302baf96+O` modulo 2^64. Its four exact byte loads are at `0x100800204`, `0x100800258`, `0x100800594`, and `0x100800760`; their addresses are BUF+O+j, j=0..3. The candidate supplies O=0. W16=`0xc8` selects return `0x100615a1c` with IA modifier `0x232d`.

For A=BUF+O+j, the canonical byte mask m(A) is:

```text
s = ROR64(A & ~7, 8) + 0x622c5d3364e5d59f
x = s XOR 0xa7bebfcf1750d389
y = s XOR 0xb6dc5654307e7f72
for q in [0x324a764c67af2e0e, 0xe70987b7a1f527b0,
          0x9032dc5079388982, 0x144db9b1af6b5721,
          0xeb8e58819a88bf30, 0x7faaf81a732f68b4,
          0x4f99108510ad96e0]:
    x = (ROR64(x, 8) + y) XOR q
    y = ROR64(y, 61) XOR x
m(A) = (x >> (8 * (A & 7))) & 0xff
W4 = BE32(BUF[O+j] XOR m(BUF+O+j), j=0..3) XOR 0x8b3dc651
```

Every state operation is u64; the final result is u32. The final y update is unused. Four source seed lemmas, 28 source round lemmas and one address/merge lemma establish this contract. The fourth source word has an additional uniform `0x5353535353535353` XOR at the final cut; the merge accounts for it. The proof does not silently equate that intermediate word with the other three.

The header writer's clear identifier representation is HE XOR `0x8b3dc651`; decoding therefore returns HE, the representation actually saved by lookup. This closes the constructor-header-to-lookup equality join. It does not identify the application meaning of every identifier. Decoder preparation has 386 instructions; only preservation of X1/X4/X16, absence of calls and its pure constant tail are certified here. Completion of its other context reads remains a premise. [LK1-LK4]

## Miss append and matched replacement [LK1-LK6]

The exact-miss path selects `0x1006f0208`; prior append evidence establishes the empty-container store `STP NEW,NEW,[C]` at `0x1004def68`, or nonempty-tail linkage at `0x10069a4a0`. This increment establishes the lookup-status join into those routines.

On a match, `0x100873ecc` reloads OLD from K+`0x80b8` and NEW from K+`0x38a0`. Its stores and subsequent conditional patches preserve OLD's position:

| Source stage | Effect |
| --- | --- |
| `0x100873f0c`, `0x100873f14` | NEW.prev=OLD.prev; NEW.next=OLD.next |
| `0x1008d776c` | If PREV!=0, PREV.next=NEW |
| `0x1005d2758` | If NEXT!=0, NEXT.prev=NEW |
| `0x1006e4168` | If PREV=0, C.head=NEW |
| `0x10075118c` | If NEXT=0, C.tail=NEW |

The separate array/word-cell proof composes these source-derived link stores under aligned, disjoint, nonwrapping owners and coherent initial links/endpoints. It covers singleton, head, tail and middle cases; NEW+`0x10` and NEW+`0x18` remain unchanged, and word cells outside the conditional write set remain unchanged. This is an abstract local splice certificate, not a byte-memory, allocator, global-list or concurrency proof. Distinct PREV/NEXT is part of the owner premise.

Consequently, under a valid initial list with unique identifiers, selected insertion preserves identifier uniqueness. If later duplicate identifiers already exist, this first-match replacement leaves them in place. There is no established global duplicate-removal pass or move-to-tail operation. [LK2-LK6]

## Retirement, output-cell lifetime and continuation [LK1-LK6]

| Site | Source-conditional contract |
| --- | --- |
| `0x100831528` | Reloads OLD from K+0x80b8 and OLD_BUF=[OLD+0x18]; skips buffer release if OLD_BUF=0 |
| `0x1006c10ac` | Authenticated `_free(OLD_BUF)` call, IA modifier 0x46a2 |
| `0x1006c10b8` | After normal return, clears OLD+0x18/u64 |
| `0x100747e84` | Authenticated `_free(OLD)` call, IA modifier 0x46a2 |
| `0x100747e88` onward | Clears K+0x80b8/u64, produces W6=0x8b3dc651 |
| `0x10076de60` | Reloads the outer constructor continuation from K+0x6ed0; transfer uses IA modifier 0x151e |

The two byte-bank families use roots `(0x100e99700,0x100f4e190)` and `(0x100e99800,0x100f4e290)`. Their 512 exhaustive byte-input cases select table index `0xcc08`, original `_free` slot `0x10109ff30`, IA `0x46a2`, address diversity zero and total addend zero, under the captured-root premise. Source call targets/arguments and normal-return stores do not prove native allocation ownership, frees, PAC acceptance or completion.

K+`0x80b8` is the matched-old-node scratch cell, not a new-node result. The new node remains linked; clearing that cell does not remove NEW. K+`0x7060` is the lookup continuation, while K+`0x6ed0` is the enclosing constructor continuation. Frame aliases are epoch-dependent: decoder preparation overwrites earlier meanings, including K+`0x988`; the prior length-relay interpretation must not be propagated beyond that epoch.

## Frozen evidence and falsification [LK7-LK8]

Each of the 12 retained send profiles has five constructor lookups at the common-finish call site. Their candidate counts are `[0,1,2,0,1]`; all four comparisons take the mismatch target `0x1005bb1b0`. Across profiles this yields 60 lookups and 48 comparisons, each reaching the append/constructor-return path. A sixth generic-helper entry belongs to another caller at `0x10074aba4`, with two mismatches and continuation `0x1004e9b70`: 12 additional episodes and 24 comparisons. It is not counted as a constructor lookup.

No retained constructor episode reaches either retirement call. All recorded authenticated transfers in these private synthetic profiles bypass authentication. The profiles support miss-path historical occurrence and sequencing only. Matched replacement, ownership and native delivery remain source-conditional/unknown, not observed. Original trace identity remains SHA-256 `78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e`; the historical failed `IOServiceOpen` does not establish a live FairPlayIOKit session.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| LK1 | Pinned thin build, original fixups/table roots and phase 0x6cf4; all source contracts | Rehash bytes, recapture fixups, establish actual bank roots/phase; different build or root falsifies transfer |
| LK2 | Valid stable finite acyclic list, coherent reciprocal links/endpoints, disjoint owners; first-match termination/splice interpretation | Independently establish owner extents and list invariants; a cycle, alias or inconsistent endpoint invalidates the global interpretation |
| LK3 | Readable shared frame, 32 B node and >=4 B candidate buffer; decoder preparation completes | Check all actual read owners and register liveness; preservation alone does not prove read validity |
| LK4 | Component stitching uses the recorded private interfaces and continuation state; decoded equality join | Independently trace incoming phase, roots and preserved registers; another continuation or clobber falsifies the stitch |
| LK5 | Normal allocator ABI/returns and exclusive distinct OLD/NEW allocations; retirement effects | Establish actual allocation lineage and call completion; aliasing or nonreturn invalidates lifetime claims |
| LK6 | Initially unique identifiers if uniqueness is claimed; no atomicity/concurrency premise is supplied | Enumerate the initial list and synchronization; pre-existing duplicates survive first-match replacement |
| LK7 | Frozen profiles accurately retain the private generator output; historical miss occurrence only | Recount site/target/episode boundaries; alteration controls reject count, hit-target and observation relabeling |
| LK8 | No native endpoint inference from source/private profiles; Mach pairing unknown | Requires independent native caller/receiver identity and matching message/selector contract evidence |

## Bounded continuation

| Impact | Remaining opportunity or constraint |
| --- | --- |
| High | Establish native phase/bank/owner provenance before promoting conditional constructor/retirement contracts to execution claims |
| High | Resolve FairPlayIOKit selector 26 and RPC 502/700 caller/receiver pairing; this increment identifies no new Mach port |
| Medium | Complete constructor type admission, 8 B scalar serialization and failure cleanup at 0x1008c3528 |
| Medium | Join identifier-specific callers to semantic record names using independently corroborated call sites; encoding equality alone supplies no name |
| Low | Frame-epoch and two-level continuation distinctions prevent erroneous cross-routine aliases in later annotation |

## Scoped quality gates

QG1: No normative conclusion is needed; findings concern source and evidence contracts.

QG2: LK1-LK8 state premises, dependencies and falsification probes.

QG3: This increment covers lookup/decoder/status/append/replacement/retirement/continuation and separates constructor/other-caller observations. Broader interface investigation remains active.

QG4: Widths, BE32 byte order, rotations, modular arithmetic, B extents and O(k)/O(1) bounds are explicit; reproducible extraction and queries are linked.

QG5: Signed status classification, fourth-word XOR, null-output behavior, first-match duplicates, frame epochs and absent matched observations are reconciled. Native and failure-frontier questions remain explicitly unknown.

QG6: Original-source bytes/fixups, frozen profiles, tool/dependency hashes, recapture, solver queries and eight altered controls provide scoped provenance. No external authority is asserted.

QG7: Bounded high/medium/low continuations are recorded; no new native execution, emulation, IPC endpoint or full-goal completion is claimed.
