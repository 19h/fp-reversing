# Identity cache population, consumption and the next record input

The declared short-path components now connect the original identity digest to a 36-byte cache owner and back into a new SHA-1 context. The source appends 12 nonzero sampled bytes to the canonical 20-byte digest, processes the resulting 32 bytes in two 16-byte groups, and writes cache bytes 0..31. A second table-driven routine consumes those 32 cache bytes. Its 32-byte intermediate passes through an address/table-dependent byte codec; the first 20 recovered bytes equal the original digest XOR0x98 and are copied into the new context. The next input requests 20 bytes at a registry-derived base+0x238. Execution stops before its first byte read: the fixture supplies a scalar registry value, not an owner for that memory. Native caller continuity, actual hardware identity values and driver IPC linkage remain unknown. The full daemon/kext/deeper-interface investigation remains active. [CP1-CP16]

This extends the [digest-completion report](daemon_digest_completion_report.md) and the earlier [identity preparation](daemon_identity_cache_report.md), [hardware-property formatting](daemon_cache36_report.md) and [lookup/clock](daemon_object_clock_report.md) evidence. These are source-level component compositions with declared library outcomes. They do not resume the original unknown-frame frontiers or establish one continuous native execution.

## Source identity and evidence boundary

| Evidence | Verified extent |
| --- | --- |
| Daemon specimen | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Main cohort | 288 reconstructed short-path states, each with two void-ABI outcomes: 576 declared executions |
| Main source visits | 42,073,344; includes 1,260,288 modeled internal transfers and 4,608 modeled imported calls |
| Main emulated A64 instructions | 40,808,448 after excluding those modeled transfers/calls |
| Main ordered effects | 6,151,680 reads / 1,550,016 writes |
| Original code inventory | 98 observed contiguous ranges / 14,736 mapped words; includes the decoded but unexecuted foreign-frontier word |
| Local proof spans | Four named aliases/captures, including 8 additional bytes from the earlier format-result capture |
| Read-only current IDB | Target `6b117c693e3b`; 28 ranges / 4,288 bytes, raw identical |
| Original pointer metadata | 139 used chained fixups, independently checked |
| Source equations | 11 rebuilt obligations / 22 original-normalized SMT artifacts; 161 lifted source instructions; no source-register rewrites |
| Independent executor comparison | 12 complete legacy/cached stream comparisons, spanning three SP placements, two cache placements, three messages and both ABI outcomes |
| Explicit ABI samples | Two cases / 164 cutpoint snapshots, with undefined fields marked |
| Controlled cache relocations | Three baseline runs / six relocated-owner runs, independently audited and replayed |
| Independent generator reference | 1,078,272 word updates / 1,728 complete624-word twists in the main cohort |
| Independent byte-codec reference | 11,520 lookup/address/value checks and fresh ABI-entry checks |

[Reconstructed contexts](triage_evidence/daemon_cache_publication_context.json), [main profiles](triage_evidence/daemon_cache_publication_profiles.json), [contracts/inventory](triage_evidence/daemon_cache_publication_contracts.json), [source equations](triage_evidence/daemon_cache_publication_proofs.json), [byte-codec model](triage_evidence/daemon_cache_publication_model.py), [ABI samples](triage_evidence/daemon_cache_publication_interfaces.json), [executor comparison](triage_evidence/daemon_cache_publication_executor_comparison.json), [main checks](triage_evidence/daemon_cache_publication_checks.json), [relocation profiles](triage_evidence/daemon_cache_relocation_profiles.json) and [relocation checks](triage_evidence/daemon_cache_relocation_checks.json) retain the evidence. [Preservation](triage_evidence/daemon_cache_publication_preservation.json) and [scoped gates](triage_evidence/daemon_cache_publication_quality_gates.json) seal the increment.

Addresses, offsets and constants below use explicit hexadecimal 0x notation. Extents/counts are decimal bytes unless stated. Arithmetic wraps modulo2^32 or modulo2^64 as indicated. F denotes the outer SP. D is the 64-byte destination reservation introduced in the preceding reports; K is the distinct 36-byte heap-cache owner. B is a separate borrowed stack-record base; C2=B+0x28, S=B+0x8C and T=B+0x150. No native fairplayd process, framework, allocator, Mach/IOKit operation, hardware PAC or IDB mutation executes.

## Restored inputs, frame pointer and cleanup

All 288 states are rebuilt from frozen entry groups and the original ordered effects, with recorded API writes and invalidations applied at their actual source positions. The audit covers 401,568 retained source visits, 46,176 reads, 28,224 writes and 1,728 declared API summaries. The original short-path stop remains ABEE7C before F+0x2E50. F+0x3050 and F+0x2E50 remain undefined in the composed inputs.

The new phase starts at 0x100BB1620 with the preceding eight declared live registers plus the borrowed X29 frame pointer. Every retained short-path record has X29=F+0xDF40. A bounded audit finds no X29 writes in 66 named spans from the preceding compression/frame/serializer/completion reports. That supports the local handover premise; it does not prove full native-path preservation.

Two values cross an explicit component boundary: the actual source-produced encoded output20 from the preceding core/serializer profiles, and the saved context pointer required at F+0x2A70 by the serializer contract. No hash oracle substitutes for source execution; independent SHA-1 expectations only check the transferred values. The three modeled messages are empty, ASCII `A`, and U+00E9 encoded as UTF-8 bytes C3A9. They are independent declared CF formatting/conversion outputs, not recovered native device strings; feasibility as the actual five-object formatting result is unknown.

F+0x3650 is no longer an unexplained input within these models: 0x100AD6FD0 stores the formatted CF object's full X0 return there. The source-local capture is proved for every u64 return. The following cleanup requests are observed in every main case:

| Call site | Import / X0 role |
| --- | --- |
| 0x1009D5168 | CFRelease: modeled SerialNumber answer |
| 0x1009E0C28 | CFRelease: modeled WifiAddress answer |
| 0x100A05408 | CFRelease: modeled BluetoothAddress answer |
| 0x100B24140 | CFRelease: constant empty CFString at 0x1010B1A18 |
| 0x1009B7640 | CFRelease: formatted signed chip value |
| 0x100B9F658 | CFRelease: modeled UniqueChipID answer |
| 0x100916248 | CFRelease: formatted identity object saved at F+0x3650 |
| 0x100B03B68 | free: allocated UTF-8 conversion buffer |

The seven release sites use original slot0x1010A02E0, IA diversity0x1883, import ordinal123. The free site uses slot0x10109FF30, IA diversity0x46A2, ordinal141. Both have zero total addends. The [SDK source](triage_evidence/daemon_cache_publication_sdk.c) and [compiled assembly](triage_evidence/daemon_cache_publication_sdk.s) verify installed arm64 pointer width and the void signatures. The daemon's build SDK remains unknown. A release request does not establish an object's native reference count or lifetime.

The void-call models independently vary caller-clobbered GPR values, NZCV and the arbitrary value left in X0 (0 versus all ones), while preserving SP and X18-X29. The private free model removes the conversion-buffer owner and invalidates its bytes. Source accesses to unknown owned bytes or unavailable foreign owners stop before execution. API register/effect checks are separate from native library behavior.

The checked instruction streams read none of X0-X17 or NZCV after a void call before overwriting the relevant value. This liveness result concerns the inspected paths; it does not model native library memory effects, object callbacks or reference counts. All288 paired ABI variants agree on the padded input, raw cache output, intermediate and recovered encoded prefix.

## Cache input, emission and consumption

The decoded digest occupies D[0:20]. The existing nonzero-byte sampler writes D[31],D[30],...,D[20], accepting only nonzero values for those positions. The 576 main cases contain 6,912 accepted tail stores and no zero retries. This finite observation does not establish uniformity, cryptographic entropy or native seed values.

The cache writer setup at 0x1009B56D4 carries the input and output through saved cells F+0x36F8 and F+0x3700. At the block entry 0x100A3CE28, they have been copied to F+0x2890=D and F+0x2A48=K. The observed block selector is W11=0xE113A6A7 for the first group and0xE113A6B7 for the second. Each group reads all16 input offsets and writes all16 output offsets once. The table-driven algorithm's standard identity remains unknown.

| Cache writer source PC | Offset within each 16-byte output group |
| --- | --- |
| 0x100A40AF0 | 13 |
| 0x100A40BE8 | 1 |
| 0x100A40CDC | 8 |
| 0x100A40D8C | 3 |
| 0x100A40E24 | 9 |
| 0x100A40E8C | 10 |
| 0x100A40EE0 | 12 |
| 0x100A40FDC | 5 |
| 0x100A41048 | 15 |
| 0x100A41078 | 4 |
| 0x100A41098 | 6 |
| 0x100A410CC | 0 |
| 0x100A4111C | 11 |
| 0x100A4113C | 2 |
| 0x100A41190 | 7 |
| 0x100A41280 | 14 |

The second invocation adds16 to these offsets. Thus K[0:32] becomes source-defined; K[32:36] remains undefined and is not read in the checked path. These are binary storage bytes, not a proven text, UUID or portable identifier format. The pointer-holder store from the earlier allocation prefix and the later data stores are distinct source events.

The consumer at 0x100AC1C7C subsequently reads K[0:32] in two groups and writes a distinct32-byte intermediate S. Its raw output differs from D in the checked data. It is therefore not classified as a raw inverse of the writer. The next byte codec explains the additional representation layer.

| Observed offset order within a 16-byte group | Sequence |
| --- | --- |
| Writer input reads | 15,3,4,10,1,2,14,6,0,8,7,9,5,12,13,11 |
| Writer output stores | 13,1,8,3,9,10,12,5,15,4,6,0,11,2,7,14 |
| Consumer cache reads | 12,13,11,5,7,15,2,1,4,6,0,8,14,10,3,9 |
| Consumer intermediate stores | 12,13,3,9,6,10,7,14,1,15,2,4,8,11,5,0 |

These orders and both complete footprints are checked across the finite cohort. The contracts also list every consumer store/read PC. No universal block-cipher equivalence or inverse relation is inferred from the footprints.

## Eight-round byte codec and new context prefix

The source at 0x100BE097C processes the first20 bytes of S backwards. For each input address A it aligns A down to8 bytes, computes an8-byte-aligned offset into a borrowed word table, loads one u64 word, and mixes that word with the aligned address through eight fixed rounds. It extracts the address-selected byte of the resulting word and XORs it with the input byte, writing T. All u64 operations and the final byte/address equations are recovered in the linked reference model.

The rounds use rotate-right8, addition, XOR and rotate-right61, with two additional fixed-mask AND/OR arithmetic steps. Separate universal u64 lemmas reduce those two steps. No standard cipher name is assigned to this small mixer or to the two larger table-driven routines. With the declared runtime mask255, the word-table offset is in0..248, aligned to8; a256-byte readable owner suffices for these accesses. The restored table fixture is512 bytes. Native mask values and ownership remain separate premises.

| Source interface | Exact recovered effect |
| --- | --- |
| 0x100BE09C0 | u64 word-table read for the current input address |
| 0x100BE0A60 | Read the current byte of S |
| 0x100BE0A68 | Write byte-codec result to T, offsets19 down to0 |
| 0x100D59B98 | Read T in increasing offset order |
| 0x100D59BA0 | Copy that byte unchanged into C2.buffer |

For every main case, T[0:20] and C2.buffer[0:20] equal the earlier identity digest XOR0x98. The consumer's32-byte intermediate is not itself the SHA-1 message prefix. Only its first20 bytes pass through this identified codec and copy.

At 0x100AEE670, the source tests the byte reached through F+0x26E0 and chooses a prefix length of20 for nonzero or0 for zero. This byte was set to1 by the preceding digest-completion phase, before the cache32 data stores. It is not an established cache-ready publication flag or ordering primitive. All main cases use1; the local source equation covers every u8 value.

| Borrowed record B / saved field | Role at this phase |
| --- | --- |
| F+0x3178 | B; F+0x3AB0 in the checked layouts |
| B+0x28 | C2, the100-byte SHA-1 context |
| B+0x68 / B+0x6C | Context counter words; high0, low20 after the prefix copy |
| B+0x70..B+0x80 | Five initial SHA-1 state words XOR0xF4F92DF7 |
| B+0x84 / B+0x88 | Output size20 / selector2 |
| B+0x8C | S, the32-byte consumer intermediate |
| B+0x150 | T, the20-byte encoded-prefix temporary |
| F+0x3504 | Selected prefix length0 or20 |
| F+0x30B8 / F+0x2A70 | C2 pointer aliases |

The context initialization clears its counter words and establishes the encoded IV, size and selector. The prefix copy preserves the IV while producing a logical20-byte message prefix. The source also changes the scratch cursor by -64 relative to its saved X1 input; the calibrated phase input is0x51E5. Actual native record extent/lifetime is unknown. The observed T stores require bytes through B+0x163, or at least356 bytes from B under a no-wrap owner premise. Numeric adjacency to other scratch regions is not an allocation proof.

This B layout is a different phase from the earlier128-byte context reservation. A matching C+0x64 output offset does not identify a shared allocation or establish its bounds.

## Following record input and architectural data flow

The next known caller at 0x100BE25B8 loads R from F+0x2F08, passes R+0x238 as input, C2 from F+0x30B8, encoded count0x1AD72F26 (decoded20) and return index0xB5D to A0AAD0. This matches the preceding fixed20 interface proof. The scalar R comes from the earlier registry lookup's entry+8 value in these models; it is0x44440000 or0x44440001. Its native type and owner are unknown.

Every case stops before 0x10095EB00 reads the first input byte at R+0x238. No bytes are assigned to that scalar address. Under the caller's20-byte request, 568+20=588 bytes from R would be required, with no u64 address wrap; this is an access requirement, not an established allocation extent or native fault. Appending the requested20 bytes would follow the already prepared20-byte identity prefix. That append and the following finalization are not executed here.

```text
declared CF formatting / UTF-8 result
                 |
     source SHA-1 core and serializer
                 |
       encoded20 -> XOR0x98 -> D[0:20]
                                  + sampled nonzero D[20:32]
                                                |
                          table-driven writer, two16-byte groups
                                                |
                          K[0:32] in separate36-byte owner
                          K[32:36] remains undefined here
                                                |
                          table-driven consumer, two16-byte groups
                                                |
                                          S[0:32]
                                                |
                         first20 -> address/word-table byte codec
                                                |
                         T[0:20] = original digest XOR0x98
                                                |
                         copy into C2, logical prefix20 bytes
                                                |
                next requested20 bytes from registry R+0x238
                         STOP before the first foreign read
```

The two relevant caches are distinct: the36-byte owner reached through the model's pointer-holder cell0x1010C6840, and the borrowed word table reached through0x1010C8268 with mask cell0x1010C67D4. The latter supplies address-dependent codec words; it is not the identity-cache allocation. Runtime controller words, the624-word generator state and the self-text sample window retain their recorded/model provenance. No additional Mach right, descriptor, message, IOKit selector or emission site is established by this increment.

## Controlled cache relocation

The main cohort contains nine distinct padded inputs,18 raw cache values and nine consumer intermediates. The two raw-cache variants per padded input correlate with the two declared cache placements. A separate controlled experiment isolates the cache owner address instead of attributing that correlation to address alone.

For each of the three modeled messages, the experiment takes one baseline context and changes only the known8-byte pointer cell at0x1010C6840 plus the corresponding allocation/snapshot owner metadata. The36 cache bytes remain initially undefined. All other known input bytes and incoming registers stay fixed. Two new aligned private owners,0x680003A000 and0x680003A100, are tested per context. The source itself produces all cache bytes in each fork; no output data or missing root field is patched.

| Controlled result, six relocated cases | Observation |
| --- | --- |
| Padded input32 | Identical to its baseline |
| Raw cache32 | Different from its baseline |
| Consumer intermediate32 | Identical to its baseline |
| Recovered encoded digest20 | Identical to its baseline |
| Following foreign input address | Identical to its baseline |
| Source visits | 73,044 per run;657,396 across the three baselines and six forks |

All nine runs have independent ordered-effect checks and fresh replays. This establishes a finite causal dependence of the raw storage representation on the declared cache owner address, while preserving the logical digest along the checked consumer path. It does not establish a universal encoding formula for the two large transforms, native heap-relocation behavior, identifier stability or a portable raw-cache format.

## Assumption register

| ID | Premise / dependent result | Stress or falsification probe |
| --- | --- | --- |
| CP1 | Pinned image, current IDB and original fixups / source identities | Rehash image; compare28 read-only ranges; independently decode139 used words |
| CP2 | Prior CF/property/UTF-8 outcomes are declared models / identity inputs and digest values | Rebuild288 states and all recorded effects; retain unknown native strings and formatting feasibility |
| CP3 | Nine incoming phase registers, including borrowed FP / source-component composition | Verify retained FP=F+0xDF40 and66 named-span nonwrites; require native predecessor/frame continuity separately |
| CP4 | Only source-produced output20 and the saved context pointer cross the component boundary / composed values | Match frozen payload hashes and encoded values; leave F+0x3050/+0x2E50 undefined; never resume their original frontiers |
| CP5 | Void-call ABI effects preserve SP/X18-X29 and supply arbitrary volatile values / cleanup continuation | Two full64 X0 values, two GPR/NZCV variants,12 cross-executor comparisons and overwrite-before-read analysis; native object/library memory effects remain unknown |
| CP6 | Runtime controller words, generator state and self-text window match the restored models / sampling and indirect lookup | Independent624-word recurrence and exact readbacks; source/image checks on every immutable read; native entropy/state unavailable |
| CP7 | Cache owner36 and readable padded input32 are valid / observed cache footprints | Reject undefined/outside-owner accesses; verify every byte and the untouched four-byte tail; native allocation/lifetime bounds remain open |
| CP8 | Writer/consumer group contracts are finite / bulk-transform interpretation | Check both16-byte groups in all576 cases; recover standard algorithms or universal equivalence separately |
| CP9 | Byte-codec constants, separated cells and mask255 apply / local universal equations | Check11 obligations, nonempty domains, word-table offsets0..248 and11,520 fresh ABI entries; native mask/word-table ownership remains unproved |
| CP10 | The marker denotes a local digest-completion condition / prefix length gate | Prove every u8 zero/nonzero case; retain source order before cache data stores; do not assign cache-ready or synchronization semantics |
| CP11 | B is a borrowed record with the required accesses / C2,S,T geometry | Check B+0x28/+0x8C/+0x150 and actual widths; require356-byte no-wrap extent for the observed T stores; do not borrow bounds from another phase |
| CP12 | Registry entry+8 supplies the following base scalar / fixed20 interface | Trace its exact saved-field use and stop before R+0x238; recover native type, owner and588-byte minimum access range separately |
| CP13 | Controlled relocation changes only the declared cache owner/root / finite causal result | Rebuild patches byte-for-byte, keep undefined cache bytes undefined and rerun all nine cases; native relocation remains untested |
| CP14 | Installed SDK declarations model the imported arm64 calls / call signatures | Compile type/width assertions and hash headers/assembly; original target build SDK remains unknown |
| CP15 | Logical authentication, private emulation and source proofs have bounded coverage / verification claims | Check original slots/modifiers and two executor streams; no native PAC, host framework or IPC operation executes |
| CP16 | Recovered digest bytes are still separate from driver transport / architecture | Require actual caller, owner, emission and matching driver-consumer evidence before joining the cache to a Mach/IOKit transaction |

Whole-component results depend on CP1-CP8 and CP14-CP16. The byte codec additionally uses CP9. Marker/context interpretation uses CP10-CP11, the foreign-input boundary uses CP12, and the relocation result uses CP13. All scopes preserve the original native and owner unknowns.

## Bounded continuation opportunities

| Impact | Unresolved interface or pattern | Required next evidence |
| --- | --- | --- |
| High | Registry-derived R+0x238 is now the next20-byte data boundary | Identify the actual registry-value producer, type, lifetime and bytes; do not fill the fixture scalar address |
| High | Cache32 carries a digest recoverable by the checked composite consumer | Recover both large transforms and prove the composite relation for arbitrary admitted inputs, owners and runtime states |
| High | Raw cache bytes change under controlled owner relocation | Recover the exact address-dependent representation before interpreting copies, persistence or cross-owner transfer |
| High | Source marker order differs from full cache population order | Recover actual readers and synchronization/reentrancy context; no concurrent visibility conclusion is established here |
| High | Native daemon/kext data-flow join remains absent | Match resulting owner/bytes to known Mach/IOKit emission sites and the corresponding driver inputs |
| Medium | B includes SHA-1 context, intermediate and temporary fields | Recover its original allocation/cursor producer and full record contract with per-phase bounds |
| Medium | Two distinct cache facilities and a self-text sampler share the phase | Separate native word-table publication, mask/seed lifetime and identity-cache lifetime through actual callers |
| Low | Legacy/cached execution differ only in implementation cost | Retain semantic stream comparisons and undefined-byte masks; do not treat elapsed time as target behavior |

The [zut trace report](zut_trace_report.md) remains separate runtime evidence. It does not corroborate this composed cache path. Original input files, IDBs and memory notes are unchanged.

## Reproduction and scoped quality gates

Use the pinned Python/Z3 environment from the preceding reports. In `triage_evidence`, run `capture_daemon_cache_publication.py`, `compare_daemon_cache_publication_executors.py`, `sample_daemon_cache_publication.py`, `probe_daemon_cache_publication_fast.py`, `recover_daemon_cache_publication.py`, `prove_daemon_cache_publication.py`, and `validate_daemon_cache_publication.py`. Then run `probe_daemon_cache_relocation.py` and `validate_daemon_cache_relocation.py` for the controlled forks. The slow reference executor is retained in `probe_daemon_cache_publication.py`.

The accepted full cohort uses cached source decoding and is freshly replayed with additional ABI observations. The [legacy-sweep audit](triage_evidence/daemon_cache_publication_legacy_sweep_audit.json) records the interrupted unpublished duplicate and verified replacement reason. Twelve full legacy/cached instruction, effect, pointer-provenance and API streams agree; unknown physical fill bytes are excluded from semantic comparison. No case set is reduced by that replacement.

Time is O(retained visits/effects + source bytes + new visits/effects + solver resources); memory includes compressed cohort artifacts, the largest decoded/fresh case, private mappings, decoder cache and SMT DAGs. The byte mixer has eight fixed rounds and O(1) time/space per byte. The two large transforms are not assigned a general algorithmic complexity beyond their observed bounded invocations. Solver queries have a30-second limit; no polynomial solver bound is claimed.

QG1: factual technical scope. QG2: CP1-CP16 register dependencies and probes. QG3: cache population/consumption, cleanup and next-input increment covered; full objective remains incomplete. QG4: explicit byte/word extents, u32/u64 arithmetic, counter order, units and modeled versus emulated counts. QG5: local universal identities, finite causal/stream evidence, original stopped frontiers and native ownership/transport limits are distinguished. QG6: original code/fixups, current IDB, SDK signatures, rebuilt formulas, independent byte/generator references and fresh source execution support scoped claims. QG7: impact-ranked continuation table provided.
