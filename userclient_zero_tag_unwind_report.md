# Actual zero-tag caller, command miss and restoration

The [actual zero-tag fallback completion](userclient_fallback_metadata_report.md) now continues through its saved caller. Private parser SUCCESS publishes an empty typed container T; the caller requests command tag `0x45e5918e`, observes T's empty head and receives raw lookup MISS `0xce515bda`. It saves that miss, requests T retirement, restores every one of the 14 original input observations, then requests buffer, context and workspace retirement. This holds for both retained predecessor modes and all admitted body lengths 0..4. Private parser success therefore does not establish command lookup success or an externally successful operation.

This is a conditional composition of original source bytes. Native callee effects, authentication, storage admission and the outer operation return remain unknown. No new native execution, live IDA access or IDB mutation was needed. Existing conditional [command-dispatch](userclient_command_dispatch_report.md) and [caller-return](userclient_caller_return_report.md) roles are joined here to the actual fallback predecessor; their earlier boundaries remain historical.

F, C, S, B, T and I denote the surviving frame, 4096 B context, 16384 B workspace, protected 14 B buffer, initialized 16 B typed container and original 14 B input extent. O[j] denotes the symbolic byte observed when the preceding source copied I[j]; it does not assert the absence of later native writers. D, U and L2 are the decoded tag, transformed type and body length. Selected conditions are D=0, U=0x6685 and L2<=4. PCs and offsets in tables are hexadecimal; abbreviated PCs have prefix `0xfffffe000`.

| Evidence | Identity / coverage |
| --- | --- |
| Original collection SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Checks, decoded SHA-256 | `2560e2a4bca0921c8f00a61717f25295c8d723f048c37880adefd1668fedc7f8` |
| Audit, decoded SHA-256 | `f95f738d99cb877a7a5d4dfbf38930df700a00bd9ea7a4ad934b0c3ffafb0b8b` |
| New source capture | 27 spans / 536 words; 535 composed words and one alternate-retag word |
| Carried header capture | 15 spans / 311 words; 304 composed words and seven alternate-retag words |
| Combined composition | 839 distinct source words / 1151 instruction instances |
| Additional setup custody | Two original words; 30 reconstructed saved cells / 240 B |
| New original pointer observations | 35 PC/slot observations / 33 slots |
| Bank reductions | Seven original bank pairs / 1792 exhaustively checked byte inputs |

The [extractor](triage_evidence/recover_userclient_zero_tag_unwind.py), [auditor](triage_evidence/audit_userclient_zero_tag_unwind.py), [checks](triage_evidence/userclient_zero_tag_unwind_checks.json.zst), [audit](triage_evidence/userclient_zero_tag_unwind_audit.json.zst) and [delivery verifier](triage_evidence/verify_userclient_zero_tag_unwind_delivery.py) preserve source, pointer, descriptor, saved-store and solver provenance. No concrete input contents are supplied.

## Joined control and data flow

```text
actual cut a638dc8, certified against both retained predecessor modes
  -> decode U=6685 and bounded L2; D=0
  -> private SUCCESS; C+600=T; T+0=T+8=0
  -> saved caller a656c08
  -> command request 45e5918e at a656ca0
  -> search a662ab4 -> empty T head -> raw MISS ce515bda
  -> callback a656cfc -> caller cleanup a656f00 -> S+de4=MISS
  -> typed T16 retirement request a6605c4
       [ordinary return / surviving storage premise]
  -> C+600=0 -> null auxiliary skip
  -> for j=13..0: I[j] = protected_B[j] XOR mask8(B+j) = O[j]
  -> B14 data retirement request a666188; W19=MISS
       [ordinary return / surviving storage premise]
  -> W26=MISS -> C4096 typed retirement request a666260
       [ordinary return / surviving storage premise]
  -> S16384 aligned retirement request a6662b0; W26=MISS
       [stop before native callee; guard / epilogue / outer return unknown]
```

| Contract | Source-established consequence |
| --- | --- |
| ZU1 | The finite interface at `a638dc8` is certified against both actual retained predecessor modes, rather than an independent caller fixture. All 17 read-before-write register views, 31 saved cells, 14 protected source-written bytes, empty-T side facts and weaker initial ownership agree. The source-entailed predecessor N=14 and earlier L=4 are proved before normalization; L2 remains a separate decoded field. |
| ZU2 | The saved caller's exact-success gate enters `a656c44`. The non-NULL published T selects `a656ca0`; the request carries W9=0x45e5918e, X22=T and X10=C+0x1f8. Search saves its callback/result-cell channels and reads T+0. The zero head selects the miss path without entering node decoding, scalar command decoding or command execution. |
| ZU3 | The search callback transfers from `a662b60` to `a656cfc`, modifier 0x8d28. C+0x1f8 becomes zero and W23=0xce515bda. The caller selects `a656f00`; cleanup stores raw MISS at S+0xde4 and selects destructor callback index 0x1a. This raw private status has no newly established public error-domain interpretation. |
| ZU4 | Non-NULL T follows the actual destructor bridge `a66229c`, entry `a660468` and empty-head branch to the typed-retirement request at `a6605c4`. After an explicit ordinary-return premise, STR at `a6605e0` clears C+0x600. Saved raw MISS remains unchanged. The model forbids subsequent T accesses; descriptor identity does not prove native destruction. |
| ZU5 | C+0x3c0=0 skips the auxiliary retirement branch and selects primary restoration. Source loops exactly 14 times, indices 13 down to 0. LDRB at `a6660d4`, address-keyed XOR at `a6660f0` and STRB at `a6660f4` establish I[j]=O[j]. Parser cursor F+0xa80 remains 10+L2; restoration count is the complete selected extent 14, independent of consumed length. |
| ZU6 | Source requests `_IOFreeData(B,14)` at `a666188` while W19=MISS. After an ordinary-return premise, W26 retains MISS and source requests `_IOFreeTypeImpl(site.AllocType4096,C)` at `a666260`. After that separate ordinary-return premise, it requests `_IOFreeAligned(S,16384)` at `a6662b0` with W26=MISS. These are source call boundaries, not observed native releases. |
| ZU7 | Every dynamic access has one source-affine owner/offset and lies in its nonwrapping initial range. Exact-cell overlaps and cross-owner separation are checked. T, B and C become inaccessible to the continuation after their respective assumed returns. Historical pointer bits may survive in frame cells; this does not extend retired-object liveness. No workspace return is assumed or executed. |
| ZU8 | The composed path introduces no Mach-message emitter, port name, right disposition, IOKit selector or matched daemon transaction. Imported retirement targets are memory-management touch points. The compiler guard, workspace callee, frame restoration, RETAB, final public result and native daemon/kext continuity remain unknown. |

| Boundary | Source PC | Target / authenticated modifier | Arguments | Nominal return |
| --- | --- | --- | --- | --- |
| Empty-T retirement request | `a6605c4` | `c4ba368` `_IOFreeTypeImpl` / 0x4d6a | X0=`847bde0`, site.FPTTLV16; X1=T | `a6605c8` |
| Primary-buffer retirement request | `a666188` | `c4ba84c` `_IOFreeData` / 0x085d | X0=B; X1=14 B | `a66618c` |
| Context retirement request | `a666260` | `c4ba368` `_IOFreeTypeImpl` / 0x4d6a | X0=`847ba60`, site.AllocType4096; X1=C | `a666264` |
| Workspace retirement request | `a6662b0` | `c4b9a24` `_IOFreeAligned` / 0x84ff | X0=S; X1=16384 B | `a6662b4`, pending |

Each instruction is BLRAA. Original collection symbols and typed descriptor bytes corroborate the target and allocation-site identities. The modifier values are source arithmetic results; native PAC success remains unknown. At each of the first three boundaries the auditor forgets X0..X18 and X30, preserves callee-saved registers/SP and surviving storage under an explicit ordinary-return premise, then forbids accesses to the retired owner. The final workspace request is left pending. No imported callee is executed, summarized as a successful release or assigned an unobserved return value.

| Local field / channel | Value and lifetime |
| --- | --- |
| C+0x600 | 0 at actual cut; T after private parser publication; 0 after the modeled T-retirement return |
| T+0, T+8 | Both zero at actual cut; no new store to T; zero head drives the miss/destructor branches |
| C+0x1f8 | Caller result cell; cleared before lookup and remains zero for empty search |
| S+0xde4 | Saved raw MISS after caller cleanup; retained through restoration until workspace retirement request |
| C+0x3c0 | Zero auxiliary pointer; no auxiliary free request occurs on this selected path |
| C+0x90 | B, used for primary restoration |
| F+0x8f8 | I, the original input pointer used by the restore loop |
| S+0xe10 | 0x621745fcc03f95d4 + 14, the encoded original-extent channel |
| F+0xa80 | Parser cursor 10+L2; restoration does not force cursor=14 |
| W19, then W26 | Raw MISS is loaded for primary retirement and transferred to a callee-saved status channel before context retirement |

For L2=0..3, private parsing leaves 4..1 B unconsumed. The restore loop nevertheless writes those suffix bytes along with the consumed header/body bytes. Its output equals the preceding source-copy observations; equality to concurrently mutable native input at the later time is unknown. This supplies a source-level copy/restore role, not a cryptographic or transport interpretation of the protected buffer.

## Expanded state certificate and validation

The preceding report's 15-register/8-cell interface was sufficient for header completion alone. The caller and cleanup need 17 register views and 31 saved cells. The new auditor discovers that expanded read-before-write interface over all 1151 instruction instances and checks it at the actual earlier cut. New live register views include W5 and X6; X28 now supplies a bank root. Previously unneeded saved aliases, callback banks, controller roots, original input and encoded restoration extent are certified from the actual state.

The additional original ADD/STR at `a635c3c..a635c44` establishes F+0x5a8=C+0x1f8. The extractor independently reconstructs its 8 B value from the last overlapping original stores in all 30 retained prefix records, totaling 240 B. The carried F+0x890 alias retains its preceding source/store certificate. These are the only reconstructed cells absent from the parent model's finite memory dictionary; other required cells must already exist in the actual state.

Seven bank reductions are re-established from both original 256 B banks and original pointer slots, exhausting all 256 possible byte inputs per pair. Ten controller loads at their exact source PCs receive independent unconstrained u32 values; no cross-read stability is assumed. Every selected pointer slot, bank/controller address and private/native target/modifier is an explicit source obligation. Captured source bytes are checked against both the normalized kext and original collection. Eight alternate-retag words remain captured but unexecuted on the normal source branch.

The audit proves 18 new source queries across 12 semantic contracts, 136 expanded state-projection queries, two source-entailed domain queries and one original alias query. It re-solves 105 preceding source/projection/domain/alias obligations. All 262 UNSAT obligations retain nonvacuous premises. Ten separate actual-cut admission checks are SAT: body lengths 0..4 in each predecessor mode. Three copied-source mutations produce SAT violations. The access ledger covers 78 distinct cells and checks 591 same-owner disjoint cell pairs.

The memory ledger records every source dynamic access, ROM bank/pointer/controller range and restore write. An access must simplify to exactly one owned owner plus an integer offset. Exact distinct cells within one owner must be disjoint. Generic u64 interval and cross-owner separation lemmas establish containment without strengthening the actual predecessor's storage premises. The model uses [F,F+0x10f0), rather than an enlarged legacy frame or an extra lower bound on F. Chronological checks reject access to T after its assumed return, to B after its assumed return, or to C after its assumed return. Those initial range inequalities remain historical facts, not native liveness assertions.

Three copied-source NOP mutations must produce satisfiable violations: command-tag MOVK at `a656ca8`, output-clear STR at `a6605e0` and restoration XOR at `a6660f0`. The latter checks the inverse byte transform rather than simply replaying write addresses. A fresh delivery verifier rebuilds extraction/audit and canonical queries, checks corpus links and manifest hashes, preserves original inputs and checks all owned files for analyst paths.

For selected extent n=14, runtime restoration takes O(n) time and O(1) auxiliary space, with n protected byte loads and n original-input byte stores; other selected blocks are O(1). This is a bound on the recovered source loop, not native callees or the whole parser. Audit inventory is O(I) time/space; same-owner pair checking is O(A^2) time and O(A) auxiliary space for A cells. Extraction is O(Bin+I+256R+C*W), for inspected bytes Bin, bank rules R, prefix records C and scanned original stores W. SMT search is separate, limited to 60 s per new query and 120 s per retained query.

## Assumption register

| Assumption | Dependent results / stress test or falsification probe |
| --- | --- |
| ZU-A1: Pinned image and receipt identities | ZU1-ZU8. Rehash both images, captured words, original pointers, descriptor bytes and all helper/dependency receipts; rebuild extraction and audit. |
| ZU-A2: Same actual frame/alias epoch | ZU1-ZU7. Prove both original alias roots, reconstruct their prefix values and inspect native alias writers before generalizing beyond source composition. |
| ZU-A3: Actual retained non-NULL allocation outcome and selected D/U/L2 conditions | ZU1-ZU6. Certify all expanded live inputs against both actual modes; prove N14/L4 independently; check each L2=0..4 SAT under actual predecessor premises. Other tag/type paths are outside this result. |
| ZU-A4: B retains the earlier protected-copy observations until restoration | ZU2-ZU7. Certify all 14 written byte/address relations and every new protected load; check native lifetime and alias writers separately. |
| ZU-A5: Ordinary T/B/C retirement returns preserve callee-saved registers, SP and surviving storage | ZU4-ZU7. Check exact target, arguments, descriptor, modifier and nominal link; forget volatile state and prohibit later retired-owner accesses. Establish native callee effects separately. |
| ZU-A6: Initial source storage ranges are nonwrapping and separate | ZU1, ZU5-ZU7. Prove weaker ownership from actual parent; classify every access, check overlapping cells and independent interval lemmas. Native allocation validity and concurrent access remain unknown. |
| ZU-A7: Normal pointer branches and finite source lift are adequate | ZU1-ZU7. Prove normal guards from actual state, cover all 839 selected words, exhaust original byte-bank identities and reject three source mutations. Native PAC and alternate paths remain unknown. |
| ZU-A8: Private status and source-call boundaries retain their stated scope | ZU3, ZU6, ZU8. Follow the pending workspace callee, compiler guard, epilogue and actual external caller before assigning public status, complete operation semantics or daemon transaction identity. |

## Bounded continuation

| Impact | Specific next interface / falsification target |
| --- | --- |
| High | Continue from pending workspace request `a6662b0` through its ordinary return, original stack guard, frame restoration and RETAB; distinguish a local status decode from externally observed behavior. |
| High | Compose nonzero-tag construction at `a642454` with node/body allocation and append, retaining actual D/U/L2 and byte custody. |
| High | Establish a matched daemon producer/transaction for this protected header and wire type 0x50db; matching tag/type scalars alone do not establish transport identity. |
| Medium | Compose oversized-body failure at `a662440` into cleanup and compare its release/status channels against this empty-search path. |
| Medium | Test whether other admitted types or extents retain the same full-input restoration contract; this report proves only the selected 14 B fallback. |
| Low | Investigate whether zero tag has a sentinel role across actual producers and consumers; its protocol meaning remains unknown. |

## Quality gates

- **QG1**: Pass. Factual source/interface analysis requires no normative judgment.
- **QG2**: Pass. ZU-A1 through ZU-A8 identify dependent results and falsification probes.
- **QG3**: Pass. Actual caller, lookup miss, restore loop and four retirement requests are covered; the full investigation remains active.
- **QG4**: Pass. Byte extents, u32 statuses, u64 pointers, loop count, reverse indices and complexity are explicit and reproducible.
- **QG5**: Pass. Private success/miss, consumed/restored lengths, initial ranges/retired epochs and native/public boundaries remain distinct.
- **QG6**: Pass. Original bytes/pointers/descriptors/stores and independently rebuilt source, projection, solver and mutation receipts supply primary provenance.
- **QG7**: Pass. Continuations address outer return, node construction, matched daemon transport, failure cleanup and extent/type generalization.
