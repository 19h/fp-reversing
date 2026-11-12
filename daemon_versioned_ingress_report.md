# Daemon versioned ingress: source record, adapter and result selection

Subsequent admission evidence: the [frame-admission report](daemon_frame_admission_report.md) recovers the unsigned n < (word XOR 0x8b3dc651) gate, its object-word lineage and the opposite branch's frame+0x4ec remainder writer. The four actual partial paths have n=0 and decoded word28, so they reach the reader without this writer. Eleven source obligations and136 A64 replays support the stated conditional contracts; native admission and the unresolved frame inputs remain unknown.

Subsequent frame-definition evidence: the [frame-word report](daemon_frame_word_report.md) recovers a conditional producer at0x100530748 and a table-resolved less-than route to reader0x10063735c. Twenty A64 controls and ten UNSAT obligations validate that route. It is absent from the four retained partial ingress paths, which remain stopped with unknown F+0x560. Neither a native defect nor a completed IOKit join is established.

The source slice at `0x10084c9b8` constructs a record and calls `0x1004ac814`, which calls the recovered root `0x10049f358`. The record's numeric count tag is `0x73113b31`, rather than the earlier declared count-16 fixture. Caller phase `0x6cf4` produces root operation `0x871a`. Original instructions preserve this chain through the root, allocator boundaries and caller result selection in twelve cases; four further caller cases stop at a copied unspecified frame word. Four short adapter-prefix controls distinguish the actual root edge from a same-discriminator decoy.

The adapter passes a private temporary containing C-0xb0; the root increments it by0xb0, restoring C. Complete paths return delta0 through the adapter and restore caller SP. The caller reads the returned u32 and tests encoded zero, `0x8b3dc651`. All twelve completed cases select the nonzero-result continuation. Prefix/extended cases stop before arithmetic on an unspecified word at root-frame+0x560; no value is injected to continue them. Native caller admission, the full IOKit buffer connection and daemon/kext pairing remain unknown. The full investigation remains active.

Primary evidence: [producer](triage_evidence/recover_daemon_versioned_ingress.py), [source, proofs and journals](triage_evidence/daemon_versioned_ingress_checks.json.zst), [independent auditor](triage_evidence/audit_daemon_versioned_ingress.py), [A64 replays and interface joins](triage_evidence/daemon_versioned_ingress_audit.json.zst), [publication verifier](triage_evidence/verify_daemon_versioned_ingress_publication.py). Parent evidence: [enclosing root](daemon_versioned_root_report.md), [source frame roots](daemon_shared_roots_report.md), [constructor](daemon_versioned_header_report.md), [versioned request ABI](versioned_request_abi_report.md), [Mach index](mach_ports_report.md). Original thin image SHA-256: `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.

Addresses use preferred base `0x100000000`; B denotes bytes. U32/u64 arithmetic wraps at its stated width. S is the declared caller SP, R=S+0x10cb8 the source-created record, Q=S+0xba18 the caller's seed/delta cell, T the adapter temporary, and F=T-0x980 the root frame SP. C is a u64 state value, not a byte extent.

| Assumption | Dependent results | Stress test / falsification probe |
|---|---|---|
| VI1 | Image, fourteen parent receipts and eighteen source dependencies identify the analysis. | Rehash inputs, source regions, every visited opcode and used original fixup/import. |
| VI2 | Two sealed epochs are restored after121357 or145961 old visits. Native startup and entry admission remain unknown. | Check prefix opcode/read consistency and independently restore its effects. Prefix visits are excluded from new execution counts. |
| VI3 | Caller entry is an interior source slice with declared phase, controller pointers, banks and table root. Earlier shared-root evidence supplies compatible values, without proving continuity to this slice. | Retain all initial cells/registers and their source-root references. An upstream composed path or compatible capture would test continuity. |
| VI4 | A new131072 B private owner holds the larger caller frame and descendants. Source inputs have256 B declared extents, filled with0 or17; input-B null and allocation-failure controls are separate. | Start owner bytes unspecified, vary physical backing, retain exact overlays and reject unknown-dependent arithmetic/control. Native pointee semantics and required extents remain unknown. |
| VI5 | `_malloc`/`_free` use explicit return/lifetime models and PAC uses logical transfers. | Independently check source opcodes, binds, modifiers, arguments, targets and return tokens; vary volatile GPR/vector/flag backing. No native allocator or hardware authentication is claimed. |
| VI6 | The adapter temporary remains disjoint from unrelated writes until return. The selected source paths preserve this lifetime. | Enumerate all overlapping writes: adapter bias store and root increment only. Retain the general nonzero-delta contract rather than asserting universal delta0. |
| VI7 | Symbolic record/seed/stack cells are disjoint; key agreement covers arbitrary u64 record addresses. | Fresh source obligations are UNSAT; original-byte replay checks concrete addresses and effects. Aliasing records require a separate domain. |
| VI8 | Census coverage is limited to exact aligned instruction forms in original __text. PAC discriminator equality alone does not establish a call edge. | Retain full section hash, literal pattern bytes, all matching sites, collision slots and metadata envelopes; compare actual source-dispatched targets. Other materializations/forms remain outside scope. |
| VI9 | The root-frame+0x560 word is unspecified in four private partial cases; this is an evidence boundary, not a diagnosed native defect. | Retain its four byte origins, the first load and absence of prior overlapping writes. A source producer or stronger upstream/input contract must establish a value before continuation. |
| VI10 | Returned words and encoded-zero selection are source-local control contracts; public status names and transport outcomes remain unknown. | Independently replay the complete caller consumer and four isolated original-byte gate controls. No path visits the IOKit call at0x100478a04. |

No live-IDB identity or annotation is asserted. Original bytes and retained receipts provide provenance; IDA, native APIs and IPC are not executed.

```text
declared caller context + private inputs + retained image/state epoch
                            |
0x10084c9b8: source record R; phase0x6cf4
0x10084ca98: load C from source-selected global -> Q
0x10084cb04 -> 0x1004ac814
               fixed64 B + dynamic16..256 B reserve
               T=C-0xb0; update global C*0x2edd+1
0x1004aca58 -> 0x10049f358
               T+=0xb0; source count tag0x73113b31 / operation0x871a
               initializer -> preparation -> constructor
                     |                         |
              clear/null/failure          prefix/extended
                     |                         |
              result + retirement       load unspecified F+0x560
                     |                  STOP before arithmetic
              adapter delta0 -> Q
              caller SP=S+delta=S
0x10084cb18: read u32[R+8]
0x10084cb28 -> 0x1008c1710
               result == 0x8b3dc651 ?
                 yes: index0x5d45 -> 0x10085ead4  (isolated control)
                  no: index0x5d32 -> 0x1008c26d4  (all complete cases)
0x1008c1760: STOP before entering selected continuation
```

| Source interface | Recovered contract | Boundary |
|---|---|---|
| Caller `0x10084c9b8..0x10084ca38` | R=S+0x10cb8. R+0: encoded u32 count tag; R+4: encoded u32 operation; R+0x10: pointer S+0x5c48; R+0x18: u64 read from S+0xfc8. | Pointee schema and native upstream caller remain unknown. |
| `0x10084ca88..0x10084caa0` | Source selects pointer cell0x1010b63e0, loads u64 C and stores C at Q=S+0xba18. | C is loaded through original image indirection, not injected after selection. |
| `0x10084cb04 -> 0x1004ac814` | X0=R, X1=Q; original slot0x1010a16e8, IA0xfbe5. | Conditional caller roots in VI3. |
| Adapter entry | Fixed64 B reserve, FP=entrySP-16; next=`u64(C*0x2edd+1)`; dynamic reserve D=`16*((next>>60)+1)` B; T=entrySP-64-D. | D ranges16..256 B. All selected caller cases have D=16 B. |
| `0x1004ac9a4` | Store u64(C-0xb0) at T. | Source temporary lifetime checked. |
| `0x1004aca58 -> 0x10049f358` | X0 remains R; X1=T; original slot0x1010a17f8, IA0xdbd5. Root source increment at0x10049f4a8 restores T to C. | Native record admission remains unknown. |
| `0x1004aca5c..0x1004aca68` | Read u32[T]; store `u64(low16(u32[T]-low32(C)))<<4` to Q. | Delta0 in complete cases; general expression still permits nonzero multiples16 B. |
| `0x10084cb08..0x10084cb18` | SP += u64[Q]; read returned u32 at R+8. | Source-composed in twelve cases; four others stop earlier. |
| `0x1008c1730` | Update u64[S+0x16d0] by subtracting0x480. | A separate frame value; not a proven allocation/free or object pointer. |
| `0x1008c1740..0x1008c175c` | Compare returned word with0x8b3dc651 and load the selected continuation. | Source-local encoded-zero predicate, without a public error-name claim. |

Let K be low32 of the root's original address key. The caller's source key is exactly K for every u64 R, without an extra low-bit agreement premise. Its stores decode to:

```text
u32(raw[R+0] + K) = 0x73113b31
u32(raw[R+4] - K) = u32(caller_phase + 0x1a26)
operation0x871a iff caller_phase0x6cf4
```

This establishes a numeric representation, not a public byte-length interpretation of0x73113b31. The earlier count-16 root fixtures retain their stated conditional scope. The actual source-produced tag takes additional preparation paths before reaching the prior constructor. They are different domains rather than interchangeable requests. The new source engine adds ROR and rotated-register operands required by those paths; independent A64 replay checks their effects.

| Literal call candidate | Modifier | Established destination | Scope |
|---|---|---|---|
| 0x10047d3c0 | 0xdbd5 | 0x10046fc5c | Two complete adapter prefixes; excludes this site from the recovered root edge in those contexts. |
| 0x1004aca58 | 0xdbd5 | 0x10049f358 | Two adapter prefixes and sixteen composed caller cases. |
| 0x1005de76c | 0xdbd5 | Unknown | Literal candidate only. |
| 0x100b3639c | 0xdbd5 | Unknown | Literal candidate only. |
| 0x10084cb04 | 0xfbe5 | 0x1004ac814 | Sixteen composed caller cases plus original bank projection. |
| 0x100710f08, 0x1007fbdf0, 0x10093b52c, 0x100946668 | 0xfbe5 | Unknown | Literal candidates only; records and modifiers are insufficient to assign targets. |

The original fixup catalog has four distinct targets for each discriminator. The dbd5 slots name0x10049f358,0x10043c380,0x10045207c and0x10046fc5c; the fbe5 slots name0x1004ad9a8,0x10045fdd4,0x1004ac814 and0x100454030. No aligned direct B/BL to the recovered adapter/root appears in the scanned __text. This is a bounded syntactic census, not a complete caller graph. LC_FUNCTION_STARTS envelopes are retained as metadata context and do not establish semantic routine ownership.

Four original256-entry bank projections check1024 byte inputs. They resolve caller-to-adapter index0xceff/slot0x1010a16e8, the seed-pointer selection, adapter-to-root index0xcf21/slot0x1010a17f8 and the final biased table-base selection. The adapter's two-stage source load materializes the same root slot through an original rebase plus integer bias; the proof does not substitute discriminator equality for that load chain. The wrong-target adapter control selects slot0x1010a1938/target0x10046fc5c.

The source-selected global at0x1010b63e0 contains C=`0xc48d2124b50100b9` in both retained epochs. The adapter stores next=`0x09ca35366ffeddb6`, so D=16 B. The root's emitter uses its own separately retained state; these values are not universal native constants. The temporary has exactly two overlapping source writes before return: `0x1004ac9a4` stores C-0xb0 and `0x10049f4a8` restores C. This establishes delta0 for the complete paths. The caller's explicit SP adjustment then leaves S unchanged.

| Variant in each epoch | Capability | Source visits | Boundary / returned word | Allocation model |
|---|---|---|---|---|
| exclude47d | 0 | 144 | Before call0x10047d3c0 to0x10046fc5c | None |
| adapter_prefix | 0 | 145 | Before call0x1004aca58 to0x10049f358 | None |
| null_B | 0 | 435 | Caller status selection;0x74c29d88 | None |
| malloc_failure | 0 | 648 | Caller status selection;0x74c29d85 | Null malloc return |
| clear1 | 0 | 19823 | Caller status selection;0x74c29d80 | Allocate, retire |
| clear2 | 0x2 | 19823 | Caller status selection;0x74c29d80 | Allocate, retire |
| clear6 | 0x42 | 19823 | Caller status selection;0x74c29d80 | Allocate, retire |
| prefix | 0x8 | 19022 | Before unknown-dependent ADD0x10063736c | Allocate; still live at stop |
| extended | 0x28 | 76777 | Before unknown-dependent ADD0x10063736c | Allocate; still live at stop |
| clear_pattern | 0 | 19823 | Caller status selection;0x74c29d80 | Allocate, retire |

The pattern control fills both declared inputs with byte17 instead of0. It tests one input-content variation, not a full protocol-validity domain. The identical per-variant lengths across the two epochs are finite observations.

| Returned word | Encoded-zero predicate | Continuation index | Original slot | Loaded target |
|---|---|---|---|---|
| 0x8b3dc651 | True | 0x5d45 | 0x101068918 | 0x10085ead4 |
| 0x74c29d80 | False | 0x5d32 | 0x101068880 | 0x1008c26d4 |
| 0x74c29d85 | False | 0x5d32 | 0x101068880 | 0x1008c26d4 |
| 0x74c29d88 | False | 0x5d32 | 0x101068880 | 0x1008c26d4 |

The first row is an isolated positive control, not a newly completed ingress path. All twelve complete source paths select the latter continuation. Four independent original-byte controls execute20 instructions each and verify both outcomes, the table load and the separate frame-value decrement. The completed journals stop before setting the final branch modifier and entering the selected target. The target's later meaning is outside this increment.

Four partial caller paths load four unspecified bytes from F+0x560 at `0x100637368`. The following `ADD W11,W11,W10` at `0x10063736c` would transform them and is not executed. There is no preceding overlapping write to that word in any of those paths. Exact byte-origin identities survive the load and two physical backing realizations; their physical values are not promoted to definitions. The frontier therefore concerns a missing producer or input/environment premise. It does not prove an uninitialized native read, an accepted native request, or a transport defect.

There is no new incoming/outgoing Mach port, descriptor/right producer or message-emission location in this increment. Twenty-two external models comprise fourteen malloc and eight free boundaries; they are allocator interfaces. Four guest allocations remain live at the partial stops, without any native allocation. The IOKit call0x100478a04 is absent from every newly executed journal. Existing port and selector21 mappings retain their own evidence scopes.

Validation covers20 cases,352926 new source visits,59932 read events,16992 write events and22 allocator models. Forty independent A64 replays check705852 source visits,618868 register effects,610472 read B,152616 written B,33984 write effects,192 copied unspecified B and44 allocator model boundaries. The copied bytes remain unspecified; arithmetic/control consumption is rejected. Four isolated status controls add80 original-byte visits. Five contiguous source regions retain431 instructions/1724 B. The per-case source-pool sum49236 includes decoded pending boundaries and is not an executed union count.

Twelve fresh negated source obligations are UNSAT: address-key agreement, record projections, unique phase, adapter frame, next-state projection, temporary/reserve/bias, cancellation, general return delta and encoded-zero branch selection. The record-field proof composes the separately proved key lemma with the original store tail. The next-seed projection omits a noninterfering load into W4 between the original seed-setup and MADD instructions; complete paths independently execute that load. Producer/auditor complexity is O(text words+snapshot+prefix+patterns*(owner+visits+effects)) time/space; each solver query has a30 s bound. Restored prefixes, native APIs and hardware PAC are excluded from new execution totals.

| Bounded continuation | Impact | Falsifiable completion criterion |
|---|---|---|
| Establish upstream context and input producers for0x10084c9b8. | High | Compose the phase/bank/frame writers and pointee ownership to this slice, or obtain a compatible entry capture. Compatible earlier root values alone are insufficient. |
| Establish a definition/contract for F+0x560. | High | Identify a coherent source producer or justified input schema before continuing prefix/extended arithmetic. A chosen physical backing value is insufficient. |
| Follow the result-selected targets. | Medium | Establish what0x1008c26d4 and0x10085ead4 consume and whether a coherent admitted path reaches IOKit; retain the distinction between observed nonzero and isolated zero controls. |
| Resolve remaining discriminator candidates. | Medium | Prove actual table/bank materialization and record contracts for the unassigned dbd5/fbe5 sites. |
| Establish the complete buffer and native daemon/kext pairing. | High | Match every required buffer byte, connection provenance, source identities and actual method/message events before claiming transport. |

Quality gates for this bounded increment:

- **QG1**: No normative premise is required.
- **QG2**: VI1-VI10 identify assumptions, dependencies and falsification probes.
- **QG3**: Source record producer, adapter/root ABI, result consumer, memory/control flow, environment, candidate census and IPC limits are covered; the full goal remains active.
- **QG4**: Count tag, byte extents, u64 state increments, frame deltas and execution/model/control totals are distinct and reproducible.
- **QG5**: Count16 fixtures and source tag0x73113b31 remain distinct. Same-discriminator targets, complete/partial paths, conditional upstream roots and unknown physical values are not conflated.
- **QG6**: Original bytes, hashes, original fixups/banks, fresh queries and independent A64 CPU/RAM effects provide provenance. Native startup, APIs/PAC and matching live-IDB evidence remain unknown.
- **QG7**: The continuation table bounds and ranks upstream admission, unresolved data definition, result targets, remaining callers and native transport.
