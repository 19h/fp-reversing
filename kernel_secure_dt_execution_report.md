# Original serialized device-tree APIs and CPU topology composition

Original device-tree readers now execute against serialized private fixtures before original CPU enumeration, main's post-enumeration helper and bootstrap-thread construction. This replaces the earlier lookup/property/iterator/named-node output models for these cases. The actual boot environment, boot-option parser, lower receiver, native hardware effects and a matched daemon/kext/kernel transaction remain unknown. The full investigation remains active. [DT1-DT7]

```text
explicit private base/extent arguments
  original tree-global initializer
  explicit complete-RAM call frame into main
    original /cpus lookup
      original property reader and strcmp
      original recursive subtree advance
    original child iterator and property readers
    original CPU/cluster stores and selected boot-record publication
    original recursive name/arm-io scan using shared global cursor
    original return -> configuration helper -> thread copy and setter
  explicit complete-RAM CPU-initializer call frame
    declared cache/context returns and logical system effects
```

The initializer-to-main call frame and later CPU-initializer call frame are explicit cuts. The enumeration return, intervening option helper and thread-copy path use original calls/returns without resetting state between them. Seven private cases reach the original 1472 B copy; three stop at an original diagnostic or before the null boot-record load; one exercises eleven dedicated API calls. [DT3-DT6]

| Claim | Established result | Dependencies |
| --- | --- | --- |
| DT1 | Original source/fixup/symbol custody and API closure | DT-A1 |
| DT2 | Serialized node/property geometry and original global initializer | DT-A1, DT-A2 |
| DT3 | Original path/property/iterator/subtree API contracts | DT-A1-DT-A3 |
| DT4 | Recursive named-node scan, shared cursor and chip-revision input | DT-A1-DT-A3 |
| DT5 | Original environmental readers compose with topology/main/thread setup | DT-A1-DT-A5 |
| DT6 | Local proofs, independent decoder/call contracts, byte formulas, replay and controls | DT-A1-DT-A6 |
| DT7 | Mach/daemon scope and impact-ranked continuation | DT-A1-DT-A7 |

Primary provenance is collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, compiler function starts, exact nlist, chained fixups and source/data bytes. The normalized kext remains SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Reference data sufficed; no IDB was read or modified. [DT1]

Artifacts: [capture producer](triage_evidence/recover_kernel_secure_dt_execution.py), [private executor](triage_evidence/probe_kernel_secure_dt_execution.py), [independent decoder/contracts and replay](triage_evidence/replay_kernel_secure_dt_execution.py), [source audit](triage_evidence/audit_kernel_secure_dt_execution.py), [delivery verifier](triage_evidence/verify_kernel_secure_dt_execution_delivery.py), [capture](triage_evidence/kernel_secure_dt_execution_checks.json.zst), [audit](triage_evidence/kernel_secure_dt_execution_audit.json.zst). Decoded capture: 525824 B, SHA-256 `adb233d79b161abf21d40ccc4c8a2ea4c474017bfb259d7609a2d7f44dc09b96`. Decoded audit: 47494598 B, SHA-256 `d36eae06782d08b26d2575f400ab87d45e2228f772a165955b7632d841c8f71c`. [DT6]

## Source closure and exact names

Twenty captured functions contain 3469 words / 13876 B. Seventeen functions exactly match the [topology handoff capture](kernel_cpu_topology_handoff_report.md); the three additions are the global initializer, recursive subtree helper and exact `_strcmp`. The capture retains 28 strings, 18 logical data blocks, three pointer fixups and three undecoded words. Those opaque words are unexecuted. [DT1]

All intervals below are half-open. Exact original names are unknown where only a role is given; no inferred name is promoted to an nlist identity. [DT1]

| Original interval | Words | Exact name / source-supported role | Executed unique PCs |
| --- | ---: | --- | ---: |
| 0xfffffe000c6622b8..0xfffffe000c662324 | 27 | Tree-global initializer; name unknown | 15 |
| 0xfffffe000c662324..0xfffffe000c6625bc | 166 | _SecureDTLookupEntry | 128 |
| 0xfffffe000c662110..0xfffffe000c6622b8 | 106 | Property reader; name unknown | 74 |
| 0xfffffe000c5e4550..0xfffffe000c5e46d4 | 97 | _SecureDTIterateEntries | 67 |
| 0xfffffe000c6625bc..0xfffffe000c6626e4 | 74 | Recursive next-subtree pointer; name unknown | 47 |
| 0xfffffe000c5e40f0..0xfffffe000c5e4318 | 138 | Recursive key/value node scan; name unknown | 97 |
| 0xfffffe000c66051c..0xfffffe000c66054c | 12 | _strcmp | 12 |

All twelve `_strcmp` PCs are exercised. Its byte loads compare raw bytes for equality, while the mismatch return subtracts the sign-extended 8-bit values modulo 2^32. Twenty-four PCs in the intervening 34-word configuration helper and 727/969 enumerator PCs execute; full routine/path coverage is not claimed. [DT1,DT6]

## Serialized records and initialization ABI

The fixture serializer and independent decoder are separate implementations. The decoder reconstructs nodes, ordered properties, payload addresses and complete subtree ends directly from initial RAM, then verifies the fixture address index and complete root extent. Each selected node has a first `name` property and valid NUL-terminated ASCII names. Actual firmware bytes, format variants, repeated separators, overlong path components and malformed tree admission are outside this increment. [DT2,DT-A2,DT-A3]

| Record | Offset | Width | Recovered meaning |
| --- | --- | ---: | --- |
| Node header | +0 | 4 B | Property count, little-endian u32 |
| Node header | +4 | 4 B | Immediate child count, little-endian u32 |
| First property | Node+8 | Variable | Properties precede child subtrees |
| Property header | +0 | 32 B | NUL-terminated name in selected fixtures |
| Property header | +0x20 | 4 B | Payload length, little-endian u32 |
| Property payload | +0x24 | Declared length | Original returned data pointer |
| Next property / first child | After payload | Four-byte alignment | `property + 36 + round_up(length,4)` in the stated valid domain |
| Next sibling | After all properties and descendants | Variable | Original recursive subtree helper returns this pointer |

Initializer X0 supplies a 64-bit base and X1 a 64-bit extent. Original source publishes base/extent/end to globals `0xfffffe0007f8b508/+8/+16` and a u32 nonnull-base flag at +24. Its addition-carry branch precedes publication. In the successful private executions X0 remains the incoming base on return; a status-return type is not inferred. Initial globals are zero in the fixture and all eleven original initializer returns are independently checked. [DT2,DT6]

Private RAM provides 65536 B base storage and 131072 B tree storage plus separately mapped original pages. The initializer receives the exact serialized extent, not the entire allocated tree storage. Root children include an unused nested subtree before `cpus`, optional nested `bridge/arm-io`, and a final sibling. This ordering exercises original recursive skipping and recursive named-node scanning. [DT2,DT4]

## API inputs, outputs and state ownership

| Routine | Incoming registers / state | Success | Miss / exhaustion |
| --- | --- | --- | --- |
| Path lookup | X0 start node or zero for global root; X1 path; X2 node-output pointer | W0=1; writes selected node to X2 output | W0=0xffffffff; output preserved in selected calls |
| Property reader | X0 node; X1 name; X2 data-pointer output; X3 u32 length-output; X4 base; X5 extent | W0=1; writes full pointer and u32 length | W0=0xffffffff; both outputs preserved in selected calls |
| Child iterator | X0 40 B iterator state; X1 child-output pointer | X0=1; increments u64 index, publishes current child and output | X0=0; writes null output; current-child pointer and index retained |
| Subtree advance | X0 node | X0 points after the complete subtree | No separate status contract established |
| Named-node scan | X0 key; X1 value or null; X2 node-output; global cursor | W0=1; writes containing node; cursor already advanced past matched property | W0=0xffffffff; output preserved; cursor advances through searched subtree |

For property calls from the original enumerator, X4/X5 are the source-published global base and extent. The source returns data pointers into serialized records; fixture property slots and modeled property-output writes are no longer used in these executions. Zero-extended `0xffffffff` in X0 is distinct from u64 all-ones. [DT3,DT6]

| Iterator field | Width | Evidence-supported role |
| --- | ---: | --- |
| +0 | 8 B | Caller-written scope/root word; unchanged by these iterator paths |
| +8 | 8 B | Node whose immediate children are iterated |
| +0x10 | 8 B | Current child pointer |
| +0x18 | 8 B | Retained zero word in selected caller-produced state; further role unknown |
| +0x20 | 8 B | Next child index; compared unsigned against zero-extended u32 child count |

The first successful iteration computes the first child after the parent's property records. Subsequent successful calls invoke original recursive subtree advance to skip the current child's descendants. Exhaustion does not increment the index. Independent contracts compare all 40 state bytes, the output pointer and return value for every selected iterator call. [DT3,DT6]

The earlier output models intentionally represented caller paths. Original execution now establishes finer return/state semantics: absent path/property models returned zero, whereas these original routines return `0xffffffff`; the modeled iterator preserved caller-produced state and omitted the exhaustion output write, whereas original source mutates the index/current pointer and writes null at exhaustion. The prior conditional caller-path results are not a native API-equivalence claim. [DT3]

Dedicated API calls exercise `/`, `/cpus`, `/cpus/cpu0`, relative `cpu0`, `/bridge/arm-io`, absent path, present/absent property, a five-byte payload and subtree ends after nested children. Original path source initializes a component budget of 63 B; exhaustive path normalization and overlong-component behavior remain unestablished. [DT3,DT6]

## Shared scan cursor and topology composition

The named-node scan uses global `0xfffffe000cba40e8` as a mutable traversal cursor. Original enumeration initializes it to the tree base. Each property advances the cursor before key/value comparison; recursive calls continue from it into descendants. A match returns the containing node, with the cursor immediately after the matched property. Failed recursive searches leave it at the searched subtree end. Every nested scan return is checked against an independently decoded preorder search. Concurrency, reentrancy guarantees and synchronization are unknown. [DT4]

The nested `arm-io` fixtures supply two-byte and four-byte chip revisions. Original property decoding truncates/publicizes the selected value at u32 global `0xfffffe0007ef8c28`; the no-`arm-io` cases select the previous default. Complete property fixtures cover scalar widths 1/2/4/8 B, all five 16 B register pairs, sparse physical affinity values, configuration precedence and mixed cluster types. [DT4,DT5]

Seven cases publish source-produced boot CPU pointers and return through original main `0xfffffe000c639cbc`, the configuration helper, main `0xfffffe000c639cc0`, the full thread-template copy and register setter. The sixteen-CPU case consumes ordinal 15. The empty-CPU and zero-limit cases stop before the original null boot-record load. With `cpus` absent from a valid serialized root, original lookup failure selects root fallback; its first child lacks `state`, so the selected prefix reaches the original missing-state diagnostic boundary. No native fault or diagnostic implementation is executed. [DT5]

The original boot-option parser remains modeled, as do selector0e no-RAM returns and cache/context helper returns. Logical PAC/system-register envelopes remain explicit. The initializer-to-main epoch and the later main-to-CPU-initializer epoch preserve complete RAM but do not establish actual caller/startup continuity. Later thread-field mutation, CPU-data+0xa38 production, native lower-facility effects and daemon pairing remain open. [DT5,DT-A4,DT-A5]

## Independent checks and bounded coverage

Twenty new nonvacuous original-source queries are UNSAT over 72 distinct PCs/instruction instances and 52 linked-edge obligations. Four unchanged prior thread-binding/setter/block-offset/bootstrap-address contracts are re-solved. New proofs cover global publication, property status/output/packing, iterator count/index/output, lookup root/output/status, subtree packing, signed byte comparison, cursor publication and component-buffer budget. The valid-domain named-scan proof follows the original branch around the pointer-poison instruction; it retains the actual linked source edge. [DT6]

Eleven components pass 7728 independent semantic checks, including 2880 nested API entry/return contracts, independent topology/thread formulas and nonstack byte comparisons. Nested call pairing requires both the original return PC and restored SP, because recursive calls share return sites. A separate journal-state algorithm validates each API's input memory and expected output preservation, return status and state mutation. Fresh replay imports no executor and reconstructs every call pair independently. [DT6]

| Original API family | Calls / matched returns |
| --- | ---: |
| Global initializer | 11 |
| Path lookup | 16 |
| Property reader | 486 |
| strcmp | 2185 |
| Recursive subtree advance | 62 |
| Child iterator | 41 |
| Recursive named-node scan | 79 |
| Total | 2880 |

Fresh replay checks 152252 source visits / 1472 unique PCs, 28608 reads, 12550 writes, 96 declared non-tree helper returns, 1750 logical PAC/system effects, 28 explicit call epochs and 3821568 final mapped bytes. Independent formulas separately compare 3604480 dedicated-API nonstack bytes, 3448832 topology bytes, 2437120 post-helper bytes and 2437120 thread/caller bytes, cumulatively across checkpoints. These byte counts overlap; they are not disjoint physical memory. All stack bytes are checked by replay. [DT6]

Four NOP controls are rejected at original stores: end-global store `0xfffffe000c6622dc`, property-length output `0xfffffe000c66222c`, iterator output `0xfffffe000c5e464c` and containing-node output `0xfffffe000c5e41fc`. They are excluded from positive totals. The largest positive case uses 67576 source visits, under the explicit 100000-visit limit. All captured undecoded words, boot-option parser internals, lower wrapper and native cache/context/SPTM effects remain unexecuted. [DT6]

Extraction is O(K+F+I+D+N) time/space in collection bytes K, fixups F, source I, data D and symbols N. Decoder/serializer traversal is O(T) time/space in selected tree bytes T, with recursion depth bounded by fixture depth. Proof construction is O(I+Q) in source/formula DAG Q; SMT search is separate, limited to 30 s/query without a polynomial claim. Execution/replay costs O(V+J+M+T) in source visits V, journals J, mapped bytes M and tree T; sorted journal materialization adds O(J log J). Per-call decoding adds examined string/property/subtree work rather than a constant-time lookup claim. Exact little-endian u8/u16/u32/u64 arithmetic and explicit modular operations apply; no statistical error estimate is applicable. Archives use `zstd --ultra -22 -q -T1`, decoded roundtrip and decoded/nested path hygiene. [DT6]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| DT-A1: Pinned image, compiler starts, fixups and symbols identify this build | DT1-DT7 | Rehash originals, all 20 intervals and seventeen prior matches; preserve three opaque words; no cross-build equivalence |
| DT-A2: The serialized fixtures instantiate the recovered valid-domain geometry | DT2-DT7 | Independent decoder reconstructs full extent, counts, ordered property payloads, padding, node index and subtree ends; authentic firmware and other format variants unknown |
| DT-A3: Selected names, widths, tree shapes and path components cover only the declared domain | DT3-DT7 | Nested unused/IO subtrees, relative/absolute/missing paths, odd-sized payloads, property misses, iterator exhaustion and sixteen CPUs; repeated/overlong paths and malformed admission untested |
| DT-A4: Explicit initializer/main and later CPU-caller call frames permit only conditional composition | DT5-DT7 | Eleven original initializer returns, seven original enumeration/post-helper returns and copies; all 28 epochs preserve complete RAM; actual startup callers/intervening callbacks unknown |
| DT-A5: Declared non-tree helper returns and logical PAC/system effects do not establish native behavior | DT5-DT7 | Independently reconstruct all 96 modeled returns/clobbers and 1750 effects; boot-option parsing, receiver/cache/context behavior and hardware effects remain unknown |
| DT-A6: Independent decoder/contracts, byte formulas, local lifting and replay support only this increment | DT6,DT7 | Twenty nonvacuous proofs, four prior rechecks, 7728 checks, four altered-store rejections; PC/SP recursive pairing and exact journal/whole-memory replay; shared decoder/emulator limitations remain |
| DT-A7: Boot-environment contracts do not establish daemon control or Mach transfer | DT7 | Pair actual daemon/user-client/provider payloads, rights, statuses and kernel epochs; no such new transaction or Mach right observed |

No new incoming/outgoing Mach port, right or message-emission location is established. The [Mach inventory](mach_ports_report.md) remains the endpoint reference. Device-tree inputs are boot-environment inputs in this conditional analysis; direct fairplayd control over them is unknown. Selector0e remains a lower wrapper selector, not a Mach port name. [DT7]

| Impact | Next discriminating work | Evidence it could establish |
| --- | --- | --- |
| High | Execute original boot-option parsing with its actual bootargs buffer representation | Replace the remaining environmental option-output models and establish precedence/width handling |
| High | Trace the real tree-global initializer caller and copied-header/tree input handoff | Replace the explicit initializer-to-main epoch and establish actual boot pointer/extent provenance |
| High | Execute remaining main callbacks and cache/context helpers | Replace the later CPU-caller epoch and determine intervening thread/global effects |
| High | Recover CPU-data+0xa38 and later thread+0x1b8 producers | Establish lifetime of TPIDR_EL0 low48 data and later lower-block selection |
| High | Pair daemon/user-client/provider traffic with lower selector receiver evidence | Establish transaction-level payload/right/status/epoch correlation across facilities |
| Medium | Identify consumers and synchronization of the shared named-scan cursor | Establish state ownership and permitted traversal lifetimes beyond these selected calls |

**QG1** Pass: factual technical analysis. **QG2** Pass: DT-A1-DT-A7 record dependencies and falsification probes. **QG3** Pass for this increment: original API roles, geometry, inputs/outputs, cursor/state/control/data flow, topology/thread composition and Mach boundaries reported; full goal remains active. **QG4** Pass: widths, byte extents, modular arithmetic, complexity and reproducible artifacts explicit. **QG5** Pass: API miss versus iterator exhaustion, output preservation versus mutation, recursive PC/SP pairing, exact names versus roles, explicit epochs versus original returns and private versus native effects distinguished. **QG6** Pass: pinned primary bytes/metadata, reconstructed proofs, independent decoder/call/byte checks, replay and controls; coverage/native limits explicit. **QG7** Pass: bounded impact-ranked continuation above. `full_goal_complete=false`. [DT1-DT7]


## Original boot-option execution follow-up

The [boot-option execution increment](kernel_boot_option_execution_report.md) replaces the remaining declared option-output returns with original scanning/conversion before original tree readers and topology/thread setup. It establishes selected name/duplicate/radix/width/presence contracts and records all 129 logical authenticated callback calls. Authentic boot inputs, explicit startup cuts and lower/native effects remain conditional.

## Boot-environment publication follow-up

Actual boot callers publish tree globals inline at the early initializer and guarded environment publisher. The new bounded census finds no direct B/BL call to 0xfffffe000c6622b8 in three kernel executable segments. The original initializer execution in this report remains an explicit fixture epoch; it is not evidence of a native caller to that separate initializer. See the [boot-environment publication report](kernel_boot_environment_publication_report.md) for source PCs, assumptions, scoped validation and remaining boundaries.

## Original platform-return follow-up

Original tree APIs now serve actual platform clock/cache/identity/chosen and diagnostic consumers after inline tree publication, with no separate generic initializer call. Per-call contracts validate the decoded serialized bytes and outputs throughout the continuous main/platform experiment. See the [platform environment execution report](kernel_platform_environment_execution_report.md) for source intervals, contracts, assumptions and remaining boundaries.
