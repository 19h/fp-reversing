# fairplayd: alternate record storage, cached masking and halfword selection

The flag-mask-4 path of helper `0x10045f984` reads a two-byte field through U+0, unmasks each byte with an address-dependent eight-round transform and tests the decoded big-endian u16 for zero. It rejoins the previously recovered transformed-halfword gate at `0x1003209ac`. Zero selects the saved record coordinate; nonzero enters further processing. The immediate nonzero continuation checks whether the decoded cursor plus 20 is strictly below 2^32. The counted continuation is established in the [walk follow-up](daemon_record_walk_report.md). Native storage admission and daemon-kext transaction identity remain unknown. [STO1-STO6; STO-A1-STO-A6]

This is a static source contract for a path absent from the six retained helper cases. No alternative execution, guest bytes, allocator result, owner definition or native observation was added. Those cases supply the incoming phase, saved-operand producers and dispatch context; they execute the mask-4-clear reader. [STO2-STO5]

| Evidence | Primary provenance and scope |
| --- | --- |
| STO1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; 296 source instruction words and seven original authenticated dispatch words retained in STO4. |
| STO2 | [Record-selection report](daemon_record_selection_report.md), [checks](triage_evidence/daemon_record_selection_checks.json.zst), decoded SHA-256 `21a7744f9ad61f2a00d2f83941f9af190040427a655ae24507300386eb4b5108`, and [audit](triage_evidence/daemon_record_selection_audit.json.zst), `174b389bf7f0f11595520d7b8f9360afe69cb506a0efcb0b73235edc5ac7e3bd`. Storage flag, span bounds and comparison contracts are inherited, not native observations. |
| STO3 | [Cached-consumer report](daemon_cache_publication_report.md), [contracts](triage_evidence/daemon_cache_publication_contracts.json.zst), decoded SHA-256 `86546e78cc28c2d710b420d2f2aaea4e17422087fd19878da779ccb73ecc257f`, and [proofs](triage_evidence/daemon_cache_publication_proofs.json.zst), `1db3ff31544f5962c6cdea7604cab30ea54d40d5b06190d42478272af6038a60`. These qualify the comparison with the earlier consumer; its initialization epoch is not joined to this reader. |
| STO4 | [Extractor](triage_evidence/recover_daemon_record_storage.py), [checks](triage_evidence/daemon_record_storage_checks.json.zst): source words, six precursor classes, 24 saved cells/168 B with last-writer custody, seven dispatch mappings and parameter comparison. |
| STO5 | [Auditor](triage_evidence/audit_daemon_record_storage.py), [receipt](triage_evidence/daemon_record_storage_audit.json.zst): 29 nonvacuous UNSAT source obligations; four interpretation checks, comprising three SAT witnesses and one UNSAT negative control; independent replay of 138 retained instruction visits across 30 selected slices. |
| STO6 | [Publication verifier](triage_evidence/verify_daemon_record_storage_publication.py): fresh extraction/audit, canonical query comparison, exact publication delta, original-input preservation and decoded path hygiene. |

## Recovered storage interface

U is the retained 48 B object at `0x6600060000`; its model address is not a native address claim. Pointers and address arithmetic are u64 modulo 2^64. W-register arithmetic is u32 modulo 2^32. Byte counts use B. The source reads the mask and table pointer once, then loads two cached u64 values separately. It does not require them to be equal merely because their addresses coincide. [STO1, STO4-STO5; STO-A2-STO-A5]

| Source | Recovered input or effect | Scope |
| --- | --- | --- |
| `0x10048e9f4..0x10048ea28` | U+0x28 flag mask 4 clear -> `0x1003cbb0c`; set -> `0x100495c3c` | Inherited universal selector with W6=`0x6ce1` |
| `0x10049f6e8..0x10049f734` | SP+0x58 and SP+0x60 receive zero-extended u32(o+14); SP+0x50 receives zero-extended u32(o+15) | Incoming W16=`0xbff7`, W23=`u32(o-0x89271580)`; source producer and six retained phases checked |
| `0x10049f884` | SP+0x6c receives encoded cursor `u32(o+20-0x89271580)` in retained cases | Current-interval last writer, not a universal span-20 premise |
| `0x1005321c4` | SP+0xb0 receives `0x1010c8268` | Current-interval last writer of an indirect global-pointer-cell address |
| `0x100495c44` | Load B from U+0 | Alternative representation base |
| `0x100495c68` | Load M32 through X7=`0x1010c67d4` | Cached-word index mask |
| `0x100495c6c`, `0x100495c70` | Reload SP+0xb0; load W64 from global `0x1010c8268` | Cached-word table base |
| `0x100495c84`, `0x100495eac` | Load K0 and K1, each 8 B, from indexed table addresses | Separate reads; native synchronization unknown |
| `0x100495e8c`, `0x100495ff4` | Read one byte at A0 and A1 | A0=B+saved(SP+0x58); A1=B+saved(SP+0x50) |
| `0x10049601c..0x100496028` | Index `0x4dc0`, IA modifier `0xb299` -> `0x1003209ac` | Original format-12 dispatch word verified; hardware PAC acceptance unmeasured |

The saved offsets are formed with u32 arithmetic before zero extension. For arbitrary o, `u32(o+15)` need not equal an unbounded mathematical `o+15`. A source proof or native admission establishing readability and no offset wrap remains necessary for a general buffer interpretation. The earlier span gates alone accept positive spans smaller than 16; they do not independently establish that these two field bytes are readable. [STO2, STO5; STO-A3]

| Retained precursor | Selected offset o | Saved SP+0x58 | Saved SP+0x50 | Decoded initial cursor | Alternate path observed |
| --- | --- | --- | --- | --- | --- |
| Four constructor-prefix classes | 1 B | 15 B | 16 B | 21 B | No |
| Two later growth classes | 57 B | 71 B | 72 B | 77 B | No |

All six cases use flag word `0xd299e642`, whose mask 4 is clear. The 24 cell checks establish current-interval provenance of the offsets, global-cell pointer and encoded endpoint. Independent replay checks 5,376 GP/SP values, 168 NZCV frames and 48 write events. Preparation slices and individual last-writer slices intentionally overlap; 138 is a replay-visit count, not a unique-instruction or native-execution count. [STO4-STO5]

## Canonical mask and decoded field

For each address A, define the signed cached-word byte offset and mask word as follows. `ROR64` is a 64-bit rotate right; `LSR64` is logical shift right; `s32` sign-extends a 32-bit value to 64 bits. The eight round keys appear below. [STO1, STO4-STO5]

```
J(A,M) = s32(u32((low32(A) & 0xfffffff8) + 0x1cecdea8) & M)
K      = load_u64(W + J(A,M))
x      = A & 0xfffffffffffffff8
y      = K
for r = 0..7:
    x = (ROR64(x,8) + y) XOR key[r]       # modulo 2^64
    if r < 7: y = x XOR ROR64(y,61)
decoded_byte(A,K,raw) = low8(LSR64(x,8*(A & 7))) XOR raw
H = (decoded_byte(A0,K0,raw0) << 8) | decoded_byte(A1,K1,raw1)
low16(W1_at_join) = u16((H XOR 0x7390) + 14)
```

| Round r | key[r], u64 |
| --- | --- |
| 0 | `0x473c853ae26b7ab8` |
| 1 | `0x8f0490db2637da4e` |
| 2 | `0x639ff74d03d39428` |
| 3 | `0xa34408d6869aa02f` |
| 4 | `0x0a23823d71e7a74e` |
| 5 | `0x6c2f97ea7411e380` |
| 6 | `0x3d107423d6820c5f` |
| 7 | `0x71ef41f1f2e87b90` |

Sixteen universal source-normalizer lemmas reduce the two differently obfuscated byte paths to this common key sequence. Two word-core composition proofs and the full read-address/halfword composition use 32 explicit applications of those lemmas. These are proof-DAG reductions of already proved equal expressions. There are zero target-instruction rewrites or alternate target execution intervals. Monolithic word-equivalence probes without reductions timed out after 10 s per byte core; those exploratory timeouts are not counted as proofs. The delivered compositional obligations all resolve UNSAT within their 30 s limits. [STO5; STO-A4]

For M=255, J is 8 B aligned in [0,248], and each 8 B load lies within the first 256 B of the table. Alignment holds for every M32 because the pre-mask index already has three zero low bits. The 256 B bound does not hold for an arbitrary mask: a SAT falsifier is retained. Under M=255, adjacent addresses use the same table address exactly when the first address has low three bits other than 7. At a word boundary they use different table addresses. Table stability and pointer validity remain separate premises. [STO5; STO-A2-STO-A3]

| Parameter | This record reader | Earlier cached consumer |
| --- | --- | --- |
| Mask-cell address | `0x1010c67d4` | `0x1010c67d4` |
| Table-pointer-cell address | `0x1010c8268` | `0x1010c8268` |
| Word structure | Eight rotate/add/XOR rounds | Eight rounds, including unreduced arithmetic mixers |
| First round XOR key in recovered model | `0x473c853ae26b7ab8` | `0x612907e886213192` |
| Table byte offset at A=0, M=255 | `0xa8` | `0x38` |
| Shared native initialization/lifetime epoch | Unknown | Unknown |

The shared globals identify a common architectural cached-word facility. They do not establish identical codecs, interchangeable ciphertext or identical native epochs. A standard cipher identity is unknown. The mask-4-clear D/E/K reader uses the separately recovered periodic scalar serialization; this alternative source path directly tests its decoded fixed-width u16. The complete field schema and relationship between representations remain unknown. [STO2-STO5; STO-A5-STO-A6]

## Join and immediate nonzero continuation

The late merge holds universally for arbitrary first/second u32 values p,q, including upper bits left by unmasking: `W1 = u32((((p<<8)|(q&255)) XOR 0x7390)+14)`. Narrowing to u16 removes the unrelated upper bits. The comparison `low16(W1)==0x739e` is therefore equivalent to H=0 across all 65,536 possible decoded halfwords. No length-tag or variable-shift interpretation is required for this alternate field. [STO5]

```
U+0x28 mask4 set
  -> U+0 + saved offsets -> raw bytes + two indexed cached words
  -> common eight-round masks -> decoded big-endian H16
  -> H16 == 0 ?
       yes -> 0x10048d3d0 -> reload saved coordinate -> caller result store
       no  -> 0x1004bad90 -> u64(cursor32) + 20 < 2^32 ?
                 yes -> 0x10063b9bc -> counted span walk; see follow-up
                 no  -> 0x1004aa840 -> encoded-zero result store
```

| Gate / dispatch | Condition | Index | Target | IA modifier |
| --- | --- | --- | --- | --- |
| Common transformed-halfword gate | H=0 on alternate path | `0x83da` | `0x10048d3d0` | `0xd137` |
| Common transformed-halfword gate | H!=0 on alternate path | `0x3a61` | `0x1004bad90` | `0xd137` |
| `0x1004bad90..0x1004bade4` | cursor32<=`0xffffffeb` | `0x1bec` | `0x10063b9bc` | `0xcb9a` |
| Same interval | cursor32>=`0xffffffec` | `0x1bc3` | `0x1004aa840` | `0xcb9a` |

The immediate mismatch gate assumes the common comparison's incoming W16=`0xffffffec`, W21=`0xffff9684`, W24=`0x89271580`, and W15=`u32(cursor32-0x89271580)`. Its accepted upper cursor is 4,294,967,275 B; adding 20 B yields 4,294,967,295 B. Cursor 4,294,967,276 B fails because adding 20 B reaches 2^32 B. The gate rebuilds W2=`0x76d8ea80` and IA modifier `0xcb9a` before either dispatch. The STO5 proof stops before the continuation. Its complete clear-storage counted-walk result is established in the [walk follow-up](daemon_record_walk_report.md). The historical proof variable named storage_record_end32 denotes the decoded cursor in this gate; its arithmetic equation is unchanged. [STO2, STO4-STO5; STO-A2]

## Assumption register and stress tests

| Assumption / dependent results | Premise | Stress test or falsification probe |
| --- | --- | --- |
| STO-A1: all binary-specific mappings | Pinned thin-image identity and exact selected words | Reject any image, source-span or dispatch-word digest mismatch; do not transfer addresses to another build. |
| STO-A2: phase-specific source equations | Recorded phases, distinct readable cells; symbolic data values remain arbitrary | Six precursor phases and last writers checked; ten load addresses proved. Changed phases or invalid/aliased source cells require fresh admission. No native admission is claimed. |
| STO-A3: buffer/table interpretation | Readable A0/A1 and cached u64 cells; M=255 only for the 256 B bound | Arbitrary-mask SAT counterexample defeats the bound; all-mask alignment proved. Test offset wrap and p<16 separately. Positive span gates alone are insufficient. |
| STO-A4: reduced proof composition | Each replacement applies its separately proved universal normalizer lemma at the recorded source endpoint | Recompute all 16 lemmas and 29 source obligations; compare canonical SMT formulas and exact source words. Zero, all-one and arbitrary-bit inputs are included by quantification. |
| STO-A5: cross-reader architectural relation | Pinned cached-consumer model/receipts, shared global addresses | Distinct first keys and A=0 index values reject codec identity. Seek a matched global-initializer/caller epoch before asserting shared live values or lifetime. |
| STO-A6: interpretation and completeness | Private static field behavior only | Join a native producer and matched daemon-kext payload before assigning a protocol field name. Alternate path admission, complete nonzero processing, standard cipher identity and native transaction pairing are unknown. |

## Bounded continuation

| Impact | Next discriminating analysis | Result it would establish |
| --- | --- | --- |
| High | Recover writers selecting U+0 and flag mask4, including constructor/caller epochs | Representation admission, ownership, field readability and whether the alternative can occur with U+8 null |
| High | Trace alternative reader admission and matching flag/base writers; see the [word contract](daemon_alternate_word_report.md) | Caller epoch and readability premises beyond the recovered source semantics |
| Medium | Join cache-table initialization to this caller and record both u64 reads | Live mask, table size, stability and representation lifetime |
| Medium | Compare recovered fixed u16 and span fields with a matched kext-side buffer transaction | Daemon-kext schema correspondence; shared globals alone cannot establish this |
| Low | Partition saved-offset u32 wrap and short-span cases under actual producer admission | Precise valid-input domain of the two-byte reader |

## Quality gates and reproducibility

**QG1** passes: factual source/ABI analysis. **QG2** passes: STO-A1-STO-A6 identify premises, dependent claims and falsification probes. **QG3** passes for this increment: alternate byte reader, table interface, decoded comparison, saved-cell custody and immediate mismatch dispatch are covered; the full investigation remains active. **QG4** passes: widths, signed extension, modulo arithmetic, B extents and endpoint calculation are explicit. **QG5** passes: static alternate source and retained clear-path journals are distinguished; mask assumptions, proof cuts, timeouts, overlap counts, offset wrap and unknown continuations are explicit. **QG6** passes: exact binary words, original authenticated fixups, pinned upstream receipts and fresh proof/replay receipts support the claims. **QG7** passes: impact-labeled bounded follow-up is listed.

Run the extractor, auditor and publication verifier with the repository evidence directory on the Python module path and the existing Capstone/Z3 dependencies available. Selected-source and replay work is O(parent receipt bytes + selected journal bytes + 296 source words + 138 replay visits*32 + symbolic DAG) in time and space, excluding solver search. Each byte model has eight rounds and O(1) time/space. Fresh proofs use 30 s/query limits. No native target API, IPC, filesystem operation, allocation/free, hardware PAC or IDB mutation is performed. Existing primary inputs remain byte-identical; no port emission or daemon-kext exchange is newly observed.


## Counted record-span walk

The [counted-walk follow-up](daemon_record_walk_report.md) distinguishes cursor o+20 from enclosing endpoint o+p, establishes the initial 20 B minimum and proves the full clear-storage counted-span walk through exact final consumption. General word/halfword reader contracts now cover every offset residue and input bit. The source decrements a 16-bit count and rejects nonpositive, wrapping or out-of-parent advances; it does not recursively validate every nested header. Zero count can accept extra enclosing extent, and earlier positive child spans can be below 20 B. Fifty-eight nonvacuous obligations, ten scalar controls, 1,980 independent replay visits, 54 saved-cell custody checks and 19 original dispatch mappings qualify the increment. Retained cases all have count zero. The alternative word contract is established in the [subsequent reader follow-up](daemon_alternate_word_report.md); native representation admission and daemon-kext pairing remain unknown; no new port emission or native exchange is observed, and the full goal remains active.

## Alternative word reader and saved context

The [alternative-reader report](daemon_alternate_word_report.md) establishes the U+0 four-byte reader at `0x100357e2c`: four address-dependent cached-word masks, full-width big-endian u32 assembly and the common continuation interface. Its final-byte whitening cancels in assembly. It restores caller X0 from SP+0xa8 and rebuilds the phases needed by the span gates. Forty-five source proofs, four interpretation controls and 330 independent setup/custody replay visits qualify this source contract. Retained calls select the clear route; native alternative admission, cache publication epoch and daemon-kext transaction pairing remain unknown. No new port emission is established.

## Storage-selector production and retained custody

The [storage-selector follow-up](daemon_storage_flag_report.md) traces the private pointer/header/tag decision to outer SP+0x662f and the later U+0x28 reader flag. The 76 retained constructors read context J+0x1c word 6 with tag `0x4e40e176`, produce selector byte 1, and retain it through 606 intervals/1,620,162 visits and 456 phase snapshots. All 608 checked successful U exports have U+0 zero and mask4 clear. Sixteen source proofs, eight scalar controls and 4,916 independent replay visits qualify the increment. The b=0 constructor branch at `0x1008c0750`, native caller/cache epoch and daemon-kext pairing remain unresolved; no new port emission is established.
