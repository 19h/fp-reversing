# N19 outer object, context transfer, publication and cleanup interface

The N19 reader's parent is the pointer saved at shared-frame K+0x1ae8. A selected producer requests128 B through the original `_malloc` binding and saves its normal return at that cell. The reader receives OUT=OBJ+8; successful N19 completion therefore installs its separately allocated16 B record container in the outer object's second pointer cell. A later success component publishes OBJ through a different borrowed output cell saved at K+0x1d60. This is a conditional source composition; continuity of the saved cells and owners remains a premise. [OL1-OL6]

The two source gates before the selected N19 call compose to exactly F==0, where F is the u32 at K+0x53ac. An isolated reading of the second gate would also accept object-flag lowbit1, but the preceding gate diverts that case when F is nonzero. Context byte+0x6c supplies an inverted low bit at OBJ+0x7c in the selected field-transfer prefix. It controls which alternate continuation is taken when F is nonzero, rather than widening this composed N19 admission condition. F's upstream producer and application meaning remain unknown. [OL2-OL5]

The caller saves the reader's raw result at K+0x5f60 before assigning W6=0x8b3dc651 on both success and failure arms. Only an incoming exact marker takes object publication. Failure forwards the address K+0x4230, containing OBJ, into the shared cleanup routine. A pointer-cell address must not be substituted with its heap pointee. Final status consumption and complete exceptional cleanup remain unknown here. [OL3,OL6-OL8]

Evidence: [original ranges, fixups, banks and candidate writers](triage_evidence/daemon_reader_outer_lifecycle_source.json), [19 UNSAT certificates, one interpretation counterexample and six alteration controls](triage_evidence/daemon_reader_outer_lifecycle_checks.json), [extractor](triage_evidence/recover_daemon_reader_outer_lifecycle.py), [validator](triage_evidence/validate_daemon_reader_outer_lifecycle.py), [preservation](triage_evidence/daemon_reader_outer_lifecycle_delivery.json), [scoped quality gates](triage_evidence/daemon_reader_outer_lifecycle_quality_gates.json), [publication audit](triage_evidence/verify_daemon_reader_outer_lifecycle_publication.py). Adjacent primary-source contracts: [allocated N19 container and u64 codec](daemon_reader_u64_codec_report.md), [original reader allocation/caller](daemon_reader_container_origins_report.md), [shared cleanup pointer-cell contract](daemon_builder_owner_join_report.md), [collection retirement](daemon_collection_retirement_report.md), [frame/fill interface](daemon_frame_entry_report.md).

| Evidence | Verified scope |
| --- | --- |
| Original thin daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Source |13 ranges,313 instructions,1252 B;12 branch-terminated ranges and one explicit prefix |
| Translation |All299 noncall/nonbranch instruction sites;299 translated instances,254 SSA definitions |
| Metadata |22 original pointer records;20 selected slot/modifier matches;512 exhaustive bank inputs |
| Candidate census |18 SP-affine overlapping writes across the three selected frame cells;3,712,490 aligned text words scanned |
| Certificates |19 UNSAT source/algebra components,one SAT interpretation counterexample,six changed-ledger controls |
| Execution boundary |No new native/target execution, CPU emulation, API/IPC operations, IDA access, IDB changes or memory writes |

All addresses are unslid virtual addresses; offsets/selectors/constants are hexadecimal. Extents use B. Integers are little-endian u32/u64 in memory; arithmetic wraps at its stated width. K is shared-frame SP, OBJ the selected128 B allocation value, CTX the field-transfer input, OUT the borrowed outer-output address, INPUT the incoming buffer, and F the saved discriminator. These role names are analytical; complete public types and original obfuscated routine names are not established.

## Outer buffer interface, allocation and local storage [OL1-OL4,OL9]

Entry0x1009638c0 is checked under incoming W20=0x3977, X24=OUT, X23=INPUT and low32(X22)=ENCLEN. Its source effects include:

| Site | Effect |
| --- | --- |
| 0x1009638d0 | Save OUT/u64 at K+0x1d60 |
| 0x1009638d8 | Save ENCLEN/u32 at K+0x5d4c |
| 0x1009638e8 /0x1009638ec | Form R=K+0xc070+POS;save R at K+0x2290 |
| 0x1009638f4 | Reserve32 B by storing POS+32 at K+0x16d0 |
| 0x1009638f8 | Save INPUT/u64 at K+0x56f8 |
| 0x100963954 | Initialize reader extent cell K+0x285c to0x8b3dc651 |
| 0x10096398c | Internal byte-fill call: X0=R, X1=0, X2=32 B;slot0xcc9b ->0x10046faf8, IA0xac7d |

After normal fill return, the two CCMP instructions use NZCV fallback0x4. The exact allocation predicate is OUT!=0 AND INPUT!=0 AND ENCLEN!=0x8b3dc651. Under the established XOR extent convention, the last comparison rejects decoded extent zero. The source saves an encoded extent; it must not be mislabeled a returned operation status. Invalid pointers or encoded zero select0x3986 ->common local-cursor restoration with raw marker0x74c29d88. This component alone does not initialize the borrowed pointee or prove its final value.

The admitted arm selects0x3977 ->0x1008c3fac. At0x1008c4010 the original `_malloc` binding receives128 B. Its normal return is saved at K+0x1ae8 at0x1008c4014. NULL selects0x539e ->common restoration; non-NULL selects0x53a5 ->0x1008a21a8. That block writes zero/u64 at OBJ+0 and OBJ+8 and derives phase0x6cf4. It does not initialize all128 B. Original allocation bank roots0x100e99a00/0x100f4e390,key0x9c,addend0xcbdf collapse all256 byte cases to index0xcc0d, IA0x6aa4. Native root contents, allocator freshness and successful PAC remain premises.

## Selected context-field transfer [OL2-OL4]

The explicit prefix0x1006c8a10..0x1006c8a6c copies the following fields from incoming CTX in X19 to OBJ in X0:

| CTX offset | OBJ offset | Width | Value relation |
| --- | --- | --- | --- |
| +0 | +0x10 |4 B |Unchanged |
| +0x48 | +0x58 |4 B |Unchanged |
| +0x4c | +0x5c |4 B |Unchanged |
| +0x50 | +0x60 |1 B |Unchanged |
| +0x51 | +0x61 |1 B |Unchanged |
| +0x54 | +0x64 |4 B |Unchanged |
| +0x68 | +0x78 |4 B |Unchanged |
| +0x6c | +0x7c |1 B |`(source_byte AND1) XOR0x7f` |

The first load is post-indexed: it reads CTX+0 and advances X13 by0x27. This prefix also saves CTX at K+0x9b8. Bytes+0x7d..+0x7f and other omitted object fields are not presumed zero. The largest accessed destination offset is0x7c, inside the requested128 B envelope under valid-object premises. The source role and lifetime of CTX are unknown; the separately recovered112 B allocation is not equated with it. Subsequent obfuscated byte-copy loops and the continuous initializer are outside this prefix certificate.

## N19 input provenance and exact composed control [OL3-OL6]

At0x100609e2c under W12=0x4b1d, the source stages low32(X4) as ENCLEN at K+0x285c and BASE+O at K+0x82e8. BASE is loaded from K+0x3a18; O is incoming X9. It saves incoming X8 at K+0x4890, loads OBJ from K+0x1ae8 into X19, reads F/u32 from K+0x53ac, and reads RFLAG/u8 at OBJ+0x7c. The selected branch table is:

| F | RFLAG lowbit | First gate | Second gate | Result in this component |
| --- | --- | --- | --- | --- |
| Zero |0 or1 |0x4b1d ->0x100801774 |0x344e ->0x1004e1f94 |N19 reader caller |
| Nonzero |1 |0x4b59 ->0x1007eff34 |Bypassed |Alternate frontier |
| Nonzero |0 |0x4b1d ->0x100801774 |0x342d ->0x1005f3a78 |Alternate frontier |

The N19 extent staged from X4 is a separate component input from the outer ENCLEN saved at K+0x5d4c. Their equality is not established; BASE/O/extent reaching definitions remain open. The two source queries use independently quantified inputs and do not prove an equality between these extents.

Both original branches and the composed Boolean identity are checked. Under a stable field-transfer join, the alternate-frontier choice corresponds to the inverted low bit of CTX+0x6c. No authorization, process, environment or public mode semantics is assigned to F or that byte.

The second gate derives W21=0xb9a. Caller0x1004e1f94 consequently supplies X8=OBJ+8, X9=&K[0x82e8], X10=&K[0x285c], W20=0xc4dd and index0x3884 ->0x100495808. The [earlier N19 contract](daemon_reader_u64_codec_report.md) supplies the16 B container allocation and successful publication through that address. It yields this conditional graph:

```text
K+1ae8 -> OBJ : requested128 B
                +0     first child cell; initially0
                +8  -> C1 : N19 requested16 B head/tail container
                +10... selected context-derived fields

K+1d60 -> OUT : borrowed u64 output cell
                *OUT = OBJ only on the exact successful publication arm
```

The provenance join depends on stable frame cells and live disjoint owners across intervening work. It establishes a private graph and register/field interfaces; it does not establish external object exposure, native lifetime, a flat-byte-buffer result or complete parsing of INPUT.

## Raw result, success output and cleanup pointer epoch [OL3,OL6-OL8]

| Source | Checked effect |
| --- | --- |
| 0x100975d5c | Save incoming low32(X6)=RESULT at K+0x5f60 |
| 0x100975d8c | RESULT==0x8b3dc651 selects0xc022 ->0x100918d7c;every other value selects0xc04f ->0x100a0bf60 |
| 0x100975d90..0x100975d94 | Set W6=0x8b3dc651 on both arms after saving RESULT |
| 0x100918d8c..0x100918d94 | Load OBJ from K+0x1ae8 and OUT from K+0x1d60;write OBJ/u64 through OUT |
| 0x100a0bf7c | Failure saves OBJ/u64 at K+0x4230 |
| 0x100a0bf80..0x100a0bf88 | Change X8 to &K[0x4230];save that address at K+0x4a68 |
| 0x1007322e0 | Shared cleanup saves the cell address, not OBJ, at K+0x5120 |

For a valid nonzero cell address K+0x4230, the shared cleanup selects0x5096. The SMT component also retains the modular zero-address branch0x5086, rather than silently treating arbitrary symbolic K as a native mapped stack. The older [cleanup analysis](daemon_builder_owner_join_report.md) establishes the nested drain/free/clear roles under its own premises; no complete continuous failure run or final raw-result recovery is claimed here. The single SAT certificate rejects equating X8 with OBJ after the pointer-cell conversion. It constructs no target input or fault.

Success branches via0x539e to0x10092757c with W21=0x4f91. The local-cursor expression is `REST -0xb2ef +0xb2cf = REST -32 mod2^64`. Combined with the32 B reservation it restores the prior logical cursor, assuming REST is the corresponding saved value. Architectural SP is never written in these source ranges. The following continuation0x100908b50 loads its discriminator from K+0xd5c and uses signed32 comparison with0x650271e4. Its two downstream branches remain frontiers, with no public-operation meaning assigned.

## Mach ports, data-flow boundary and retained trace [OL6-OL10]

These source components perform local allocation, field/cell stores, an internal fill and authenticated internal branches. They contain no Mach-message emission site or numeric Mach-port producer. OBJ, its child container and K+0x16d0 are pointer/local-storage roles; none is identified as a Mach port. The existing [port inventory](mach_ports_report.md) retains the actual message/send interfaces and their independent evidence boundaries.

The original annotated trace remains the primary runtime artifact at `/Users/___/Downloads/zut/annotated-strace-rax-user.txt`, SHA-256 `78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e`. Its IOKit transport success must remain distinct from the reported user-client-open failure0xe00002c2 and NULL connection. This new static allocation/publication composition adds no successful daemon-to-kext selector26 or RPC502/700 exchange. The trace and original input files are checked unchanged during sealing; no trace or harness is rerun.

The whole-text SP-affine census finds18 overlapping writer candidates for K+0x1ae8, K+0x1d60 and K+0x5f60, including other-width writes and other frame epochs. Only the source-certified selected producer/consumer components above contribute to this graph. The census excludes memory-derived/non-affine aliases, unrecognized stores, opaque callees and a global reaching-definition proof. Merely finding another equal stack offset is insufficient to identify the same active object.

## Assumption register and falsification probes

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| OL1 |Pinned original thin image and unslid address mapping;all source claims |Rehash image and recapture all1252 B;any mismatch rejects the increment |
| OL2 |Original dispatch table and byte banks match the source values;selected calls/edges |Independently decode original fixups;check all512 bank cases and actual register roots before applying to native state |
| OL3 |One stable K epoch and saved cells across joins;OBJ/OUT/input graph |Find a reaching overlapping write, frame switch or callee clobber that intervenes;candidate census is not exhaustive |
| OL4 |Live valid disjoint CTX/OBJ/frame/local-output owners;field stores and allocation composition |Check concrete allocation extents and aliases in retained evidence;an alias or shorter owner refutes applicability |
| OL5 |Incoming W20=3977 and W12=4b1d at their respective component entries;allocation/admission formulas |Trace their actual upstream definitions;different modes invalidate these selected constant targets |
| OL6 |Earlier N19 contract and stable parser output reaching OBJ+8;container/publication composition |Recapture its saved OUT/continuation and return;an intervening cell write breaks the join |
| OL7 |Normal calls preserve SP/X19-X29;new caller-saved values are unconstrained;call joins |Inspect the complete selected callee ABI or a preserved trace;do not use accidental caller-saved residue |
| OL8 |Existing shared cleanup contract applies to the forwarded local cell;conditional disposal roles |Verify the stored cell address through drain/free/clear continuations and RESULT recovery before asserting whole cleanup |
| OL9 |REST at common restoration is the corresponding reserved local cursor;net cursor restoration |Follow K16d0 reaching stores;an unmatched reservation/refill invalidates the reserve/restore composition |
| OL10 |Trace is emulator-produced and retains its original bytes;runtime claims limited to that artifact |Rehash it;require separately captured successful native user-client open and correlated message evidence before native pairing claims |

## Bounded continuation opportunities

| Impact | Frontier | Evidence needed next |
| --- | --- | --- |
| High |Nested record-buffer lineage into N19 |Join BASE/O/ENCLEN producers with the key0xd719dce3 first-child lookup and its full header/type/value reader;verify actual saved cell reaching definitions |
| High |Outer object to external ABI |Follow the two0x100908b50 targets, Kd5c discriminator and K1d60 caller to any serializer or external result consumer;require exact source stores rather than numeric pointer resemblance |
| High |Daemon/kext pairing |Correlate an already available successful open/connection with exact IOKit selector, arguments, status and callback/reply identity;the supplied trace's failed open cannot establish this |
| Medium |Complete128 B initialization |Recover the excluded context-byte transfer loops and join field prefix to allocation and N19 entry;classify omitted bytes without assuming zero |
| Medium |112 B context identity |Complete its stateful helper-driven initialization and trace its publication before assigning it to CTX;equal sizes/offsets are insufficient |
| Medium |Exceptional cleanup/status |Trace the pointer cell through the shared cleanup, both children and final RESULT reload;do not infer success from the common W6 assignment |
| Low |Candidate-writer coverage |Extend store/alias recognition and frame-epoch partitioning;retain the18 current candidates as a bounded locator set |

Algorithms: the SP-affine census is O(N+H+E) time and O(H+A) retained memory for N aligned text words,H candidates and bounded live aliases A; its known-entry set adds O(E) memory. Two exhaustive byte-bank checks take512 cases. Source translation is O(I),I=313 captured instructions, with299 modeled noncall/nonbranch sites. SMT decision complexity is solver-dependent; each query has a15000 ms timeout and a20000 ms subprocess limit. Unknown/timeout is rejected. Hash/publication verification is O(total logical artifact bytes+links), with memory bounded by the manifest and largest decoded JSON/report. Logical artifact bytes may be stored in `.json.zst` after external archival migration; hashes refer to decoded contents.

## Scoped quality gates

QG1: Factual technical analysis; no normative judgment is required.

QG2: OL1-OL10 list the assumptions, dependent results and falsification probes.

QG3: This increment covers the outer object's selected producer/fields, N19 parent/admission, result/publication/cleanup and control/frontier context. The broader interface investigation remains active and incomplete.

QG4: Widths, endian, modular arithmetic, B extents, source coverage, complexity and solver limits are explicit and reproducible.

QG5: Composed versus isolated gate conditions, encoded extent versus result, heap pointer versus pointer cell, local cursor versus SP and symbolic zero versus valid mapped frame are distinguished. Unproved continuations are not represented as completed paths.

QG6: Source bytes, daemon/fixup/bank identities, exact retained queries, altered-ledger rejection and original trace preservation are independently checked. Prior conditional contracts remain identified as dependencies.

QG7: High/medium/low continuation opportunities are bounded and tied to evidence that would close each named frontier. No complete native parser, cleanup, ownership, PAC, external exposure or daemon-kext pairing result is claimed.
