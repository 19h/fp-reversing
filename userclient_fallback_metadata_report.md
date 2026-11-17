# Actual fallback header, type dispatch and empty-container publication

The [actual protected fallback](userclient_fallback_parser_report.md) now continues beyond its tag store through the remaining six header bytes. The ten-byte header yields a BE32 tag D, transformed BE16 type U and BE32 body length L2. With the source-established 14 B extent and cursor zero, the body-fit condition is exactly L2 <= 4. Selected type U=0x6685 commits a bounded payload view and metadata. D=0 publishes the initialized empty container and transfers to the actual saved caller; D!=0 enters ordinary record construction. Other type handlers, subsequent failure cleanup and the authenticated outer operation return remain unknown.

These are source compositions against the two actual retained predecessor modes. No new native target execution, live IDA access or IDB mutation was needed. F, C, S, B and T denote the existing SP, private context, workspace, protected 14 B buffer and initialized 16 B typed container. I[j] below means the symbolic byte observed by the preceding original-input copy, rather than a supplied concrete input or an independently established native buffer. Hexadecimal offsets and abbreviated PCs use prefix `0xfffffe000`; byte counts are decimal.

| Evidence | Identity / coverage |
| --- | --- |
| Original collection SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Checks, decoded SHA-256 | `4c3e3078ec44ee3b54ad6656fb72b3b7da17375e2250bbcdb1d19c45903678bb` |
| Audit, decoded SHA-256 | `d1dad65a824851f34076fc4afd20c254a49c6f9f02c4730fe20adbcf0d225e82` |
| Selected continuation | 15 spans / 311 words; 304 composed words and seven captured alternate-retag words |
| Original pointer observations | 16 PC/slot observations / 16 slots |
| Additional setup custody | Two original words; 30 saved-cell reconstructions / 240 B |

The [extractor](triage_evidence/recover_userclient_fallback_metadata.py), [auditor](triage_evidence/audit_userclient_fallback_metadata.py), [checks](triage_evidence/userclient_fallback_metadata_checks.json.zst), [audit](triage_evidence/userclient_fallback_metadata_audit.json.zst) and [delivery verifier](triage_evidence/verify_userclient_fallback_metadata_delivery.py) preserve primary byte, pointer, saved-store and solver provenance. Earlier reports retain their historical boundaries.

## Source flow and field contracts

```text
actual cut a638dc8: S+a18=D XOR SUCCESS; T is initialized; output=0
  |
  +--> B[4..5] -> U=BE16(I[4..5]) XOR 365e -> S+2a0
  +--> B[6..9] -> L2=BE32(I[6..9])          -> S+a64=L2 XOR SUCCESS
  |            candidate cursor = 10 + zero_extend32(L2)
  |
  +-- L2>4 --> metadata outcome failure --> a662440 [cleanup pending]
  |
  +-- L2<=4 --> U==a129 ---------> a639178 [handler pending]
                |
                +-- U!=a129 --> U!=6685 -> a63a790 [handlers pending]
                                 |
                                 +-- U==6685 --> payload=B+10
                                      cursor=10+L2; metadata committed
                                      |
                                      +-- D!=0 --> a642454 [construction pending]
                                      |
                                      +-- D==0 --> a6421b0
                                           -> C+600=T at a660ad0
                                           -> saved caller a656c08
                                           [caller body/outer return pending]
```

SUCCESS is raw u32 `0x31ae0066`. The final private BRAA is at `0xfffffe000a660af0`, modifier `0x481b`; its target is loaded from C+0x5c8. This is a source-established private continuation, with native PAC authentication unknown.

| Contract | Established consequence |
| --- | --- |
| FM1 | The continuation starts at the actual parent cut `0xfffffe000a638dc8`. Both modes certify every read-before-write register view and saved cell, ten source-written protected bytes, empty-container side facts and weaker live-storage ownership. Original ADD/STR at `0xfffffe000a635efc..0xfffffe000a635f04` establishes F+0x890=C+0x3d8; all 30 prefixes reconstruct that 8 B cell from their last original stores. |
| FM2 | The protected type helper at `0xfffffe000a63930c` reads B+4 and B+5. Its returned low16 value is U=BE16(I[4],I[5]) XOR 0x365e. STRH at `0xfffffe000a639dd4` stores U at S+0x2a0. The selected U=0x6685 corresponds exactly to wire bytes 0x50,0xdb. |
| FM3 | The same protected word reader used for the tag is invoked again at `0xfffffe000a637138`, now with original offset 6 and a different callback. It reads B+6 through B+9 and returns L2 XOR SUCCESS to `0xfffffe000a6390b4`. Source stores encoded L2 at S+0xa64 and u64 candidate 10+zero_extend32(L2) at S+0xcf8. |
| FM4 | For every u32 L2, the body gate at `0xfffffe000a639160` selects `0xfffffe000a639164` iff L2<=4; otherwise it selects `0xfffffe000a6423c0`, modifier `0x685a`. Rejection retains F+0xa80=0, W10=0, C+0x600=0 and raw status `0xce515bb8`, then selects cleanup entry `0xfffffe000a662440`, modifier `0xc9dc`. Cleanup itself is not composed. |
| FM5 | Direct B.NE at `0xfffffe000a639174` takes U!=0xa129 to `0xfffffe000a63a784`; equality falls through to `0xfffffe000a639178`. Direct B.EQ at `0xfffffe000a63a78c` takes U=0x6685 to `0xfffffe000a63dc9c`; other admitted types fall through to `0xfffffe000a63a790`. These gates and the subsequent selected-tag split form disjoint exhaustive categories; the uncomposed handler bodies retain unknown effects. |
| FM6 | For admitted U=0x6685, STR at `0xfffffe000a63dcc0` publishes B+10 at C+0x280. The metadata continuation commits cursor 10+L2 at F+0xa80 and copies encoded tag/type/encoded length to S+0xaec/S+0xa08/S+0x9e8. The payload half-open interval [B+10,B+10+L2) is contained in [B,B+14). W10 becomes 1 and W23 becomes SUCCESS before the metadata-kind gate. |
| FM7 | With U=0x6685 and D=0, the kind gate at `0xfffffe000a642450` selects `0xfffffe000a6421b0`, modifier `0x5ab2`. The success block stores SUCCESS at S+0xc10 and retains W23=SUCCESS. Original STR at `0xfffffe000a660ad0` writes T through C+0x188=C+0x600. T+0 and T+8 remain zero; no node construction or body copy executes on this selected path. The source then transfers to saved caller `0xfffffe000a656c08`. |
| FM8 | With admitted U=0x6685 and D!=0, the same kind gate instead selects `0xfffffe000a642454`, modifier `0x5ab2`. This is the ordinary record-construction boundary. The decoded D/U/L2 are not silently equated to preceding abstract record fields; the new length L2 is distinct from the earlier source-entailed predecessor length 4. |

| Header offsets | Width | Decoded value | Saved channel |
| --- | --- | --- | --- |
| 0..3 | 4 B | D=BE32(I[0..3]) | S+0xa18 = D XOR SUCCESS |
| 4..5 | 2 B | U=BE16(I[4..5]) XOR 0x365e | S+0x2a0 = U |
| 6..9 | 4 B | L2=BE32(I[6..9]) | S+0xa64 = L2 XOR SUCCESS |
| 10..13 | Up to 4 B | Admitted selected body view | C+0x280 = B+10 |

The parent copy established `stored_B[j]=I[j] XOR mask8(B+j)`, with the address-keyed mask given in the [parent report](userclient_fallback_parser_report.md). New reads consume that same modeled B epoch. Projection proofs certify the protected source-written value and address at every header index; no independent byte fixture replaces it. D uses four bytes, U uses two and L2 uses four, with BE assembly and u32 arithmetic. Candidate-cursor addition uses a zero-extended u32 length in 64 bits, giving 10 <= candidate <= 4,294,967,305 B; it cannot wrap u64. The predecessor's L=4 does not force these newly observed length bytes to encode 4.

## Publication boundary and scope

Private zero-tag success does not require complete consumption of the 14 B selected extent. L2=0 commits cursor 10; L2=4 commits cursor 14; L2=0..3 leaves 4..1 B unconsumed, respectively. Eight conditional profiles per mode, including zero/four/max-u32 lengths and both selected tag outcomes, are separately SAT under the actual predecessor premises. These are source-model admission checks, rather than native reachability evidence.

The output is the existing initialized T with two zero pointer fields. It is not a newly constructed record or a proof that the body was processed. B remains a separate live modeled buffer and C+0x228 still retains T. The later caller's handling of the empty container, suffix and B lifetime remains unknown. A sentinel interpretation for D=0 is a useful working hypothesis; its protocol meaning is unknown until the caller and other producers/consumers are joined.

No new imported/native call, Mach message emitter, Mach port name, right disposition or IOKit selector is established by this continuation. Private table dispatch and output-cell publication should remain separate from the [transport inventory](mach_ports_report.md). Native daemon/kext transaction identity, admission, ownership, locking and PAC remain unresolved at this boundary.

## State projection and independent validation

The parent audit reconstructs a large actual predecessor. This increment uses its finite continuation interface instead of repeating the entire instruction history inside every new decoder query. The auditor discovers every register and saved cell read before being written, compares those entry values against each actual predecessor, and proves the inherited byte and ownership facts. Unknown passthrough registers remain symbolic. It proves N=14 and predecessor L=4 before using those equalities as redundant simplification lemmas. No larger legacy frame extent or stronger disjointness assumption is imported.

The audit proves 24 new source queries across 17 semantic contracts, 78 projection queries, two source-entailed domain queries and one original alias-setup query. It re-solves 80 retained tag-result partitions. Every UNSAT obligation has satisfiable premises. Sixteen separate actual-cut admission queries are SAT. Three copied-source mutations produce SAT violations. Coverage is 304 continuation words, with seven captured alternate-retag words left unexecuted. The access ledger contains 26 distinct cells, including two entry-only T fields, and checks 70 same-owner disjoint cell pairs.

| Live saved cell at the cut | Width | Source-established value | First continued read PC |
| --- | --- | --- | --- |
| F+0x890 | 8 B | C+0x3d8 | `0xfffffe000a638e04` |
| F+0xbd8 | 8 B | 0 | `0xfffffe000a639310` |
| C+0x3d8 | 8 B | B | `0xfffffe000a639318` |
| S+0xaa0 | 8 B | 0x26120449c43b12e6, the 14 B encoded-extent channel | `0xfffffe000a6390d8` |
| S+0xa18 | 4 B | D XOR SUCCESS | `0xfffffe000a63dce4` |
| C+0x228 | 8 B | T | `0xfffffe000a642428` |
| C+0x188 | 8 B | C+0x600 | `0xfffffe000a660acc` |
| C+0x5c8 | 8 B | 0xfffffe000a656c08 | `0xfffffe000a660ae8` |

| Live register view | Value / exact scoped role |
| --- | --- |
| SP, X2, X4, X7 | F, C, S, original dispatch table 0xfffffe0008472f20 |
| W15 | 0x635c00cc |
| W19, W24 | 0x7795e642, 0x7795e3ce |
| W3, W30, W8 | 0x886a1ca3, 0x31ae0066, 0x0000001c |
| X0, X1 | 0xb68fc0720fc51d4f, 0xa615dad20fbb426c; arithmetic operands |
| X20, X26 | 0x4dae26df20976138, 0x02e859d27e491464; protection operands |
| X28 | Mapped actual predecessor value; no new semantic role assigned |

The continuation needs only the parent's [F,F+0x10f0) frame extent, rather than a larger legacy frame or an extra lower bound on F. The projection proves that ownership for all actual predecessor states. C+0x600=0 and T+0=T+8=0 are certified additional entry facts used to assess publication and field retention.

The saved-cell model is checked against every source memory access. Each dynamic access must simplify to one unique owned range and integer offset; unclassified reads fail. Same-owner cells must be disjoint unless they are the same exact cell. Independent u64 interval proofs establish nonwrapping containment and disjointness of subranges in disjoint owners. Every static pointer candidate is checked in an original image segment; source obligations check the selected slot and private transfer target/modifier. The continuation writes neither protected B bytes nor T fields. This supports the zero-field retention claim without treating an exact-cell dictionary as an alias-complete native memory model.

Three source mutations must yield SAT violations: removing the final type-transform addition at `0xfffffe000a6393bc`, removing cursor commit at `0xfffffe000a63dce0`, and removing output publication at `0xfffffe000a660ad0`. They modify copied source bytes only. A fresh delivery verifier rebuilds extraction and audit, compares canonical queries, checks all manifest/file bytes and preserves the original inputs. Native calls and concrete input contents supplied: zero.

Header decoding and this selected continuation take O(1) time and auxiliary space, with six additional protected byte loads. The audit's live-state/access inventory is O(I) time/space in inspected instruction instances; same-owner cell checking is O(A^2) time and O(A) auxiliary space for A distinct cells. Evidence construction is O(Bin+I+C*W+query-DAG size), where Bin is inspected source/receipt bytes, C is predecessor records and W is scanned stores per record. SMT search is separate, bounded at 60 s per new query and 120 s per retained query. No whole-parser termination or complexity bound is established.

## Assumption register

| Assumption | Dependent results / stress test or falsification probe |
| --- | --- |
| FM-A1: Pinned images, dependencies and predecessor identities | FM1-FM8. Rehash both images, source words/pointers, retained receipts and helpers; rebuild extraction and audit. |
| FM-A2: Same surviving frame, saved caller and F+0x890 alias epoch | FM1-FM8. Reconstruct all 30 original saved cells, prove original ADD/STR, inspect intervening alias writers and caller replacement before native generalization. No complete native alias-writer exclusion is claimed. |
| FM-A3: Actual selected non-NULL typed-allocation outcome in both retained modes | FM1-FM8. Re-solve the retained tag-result partitions and N=14/L=4 domain certificates; certify the full finite continuation interface instead of seeding an independent parser fixture. |
| FM-A4: Ordinary allocation return preserves callee-saved registers/SP and surviving storage | FM1-FM8. Retain the parent's volatile-register forgetting and exact target/descriptor/link custody; establish native callee effects separately. |
| FM-A5: B retains the preceding protected bytes in its live 14 B epoch | FM2-FM8. Certify all ten source-written header bytes, six new addresses and the normal-pointer guards; investigate native alias writers and lifetime separately. |
| FM-A6: Non-NULL T remains a writable nonwrapping 16 B extent separate from live storage | FM1, FM7. Prove weaker ownership against the actual parent, check the complete source access ledger and no store to T, then establish native allocation/reference lifetime independently. |
| FM-A7: Captured normal pointer branches and source lift are adequate for this conditional composition | FM1-FM8. Prove new normal guards from the actual predecessor, check every captured word and transfer, reject three source mutations, and keep the seven alternate-retag words/PAC outside native claims. |
| FM-A8: Source-private output and status domains retain their stated limits | FM4, FM6-FM8. Follow the exact saved caller, cleanup and node-construction frontiers before assigning external status, sentinel meaning, whole-input acceptance or protocol identity. |

## Bounded continuation

| Impact | Specific next interface / falsification target |
| --- | --- |
| High | Follow actual nonzero-tag entry `0xfffffe000a642454` into node allocation, body ownership/copy and append; retain the newly decoded fields' byte custody. |
| High | Follow the zero-tag saved caller `0xfffffe000a656c08`; establish its empty-container, unconsumed-suffix and B-retirement behavior before assigning protocol meaning. |
| High | Follow oversized-body entry `0xfffffe000a662440` through T/B cleanup, status propagation and the compiler guard/frame/RETAB. |
| High | Identify a matched daemon producer/transaction for the recovered protected header and 0x50db wire type; a matching scalar alone is insufficient. |
| Medium | Recover U=0xa129 and remaining-type handler effects, including whether their length/cursor conventions differ. |
| Medium | Generalize actual-prefix compositions beyond the selected 14 B extent and two retained modes; preserve independent tag/type/length domains. |
| Low | Refine source-role names only after caller/consumer continuity establishes the zero-tag record's function. |

## Quality gates

- **QG1**: Pass. Factual source/interface analysis requires no normative judgment.
- **QG2**: Pass. FM-A1 through FM-A8 identify dependencies and falsification probes.
- **QG3**: Pass. The actual header, body bound, first two type gates, selected metadata and zero-tag private publication are covered; the full investigation remains active.
- **QG4**: Pass. Byte extents, BE fields, u16/u32/u64 widths, zero extension, bounds and complexity are explicit.
- **QG5**: Pass. Earlier/new field domains, empty-container output, suffix behavior, handler boundaries and native limits are separated.
- **QG6**: Pass. Original words/pointers/stores and independently rebuilt projection, solver and mutation receipts supply primary provenance.
- **QG7**: Pass. Continuations address construction, saved-caller/suffix handling, rejection cleanup, wider types/extents and matched transport.
