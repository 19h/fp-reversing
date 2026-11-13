# Complete mask loop, shared buffer publication and post-exit interfaces

Current cache-codec increment: The [cache-codec continuation](daemon_return_cache_codec_report.md) gives the published 255 word an explicit mask role in another caller: sign extension and AND 0xffffffffa96e0c84 select cached u32 offset 132. Original initializer writers for both root cells are established in twelve scoped paths. Separate caller premises preserve the unresolved lifetime join.

The selected callback paths now execute **all 128 in-place u32 XOR updates covering 512 bytes**, publish the buffer through global cell `0x1010C8268`, and normalize sixteen words in its first 256 bytes. The publication guard requires a 4-byte-aligned pointer and an empty cache cell under the recovered phase. A separate global u32 at `0x1010C67D4` receives 255. This increment established its publication; the cache-codec continuation above now corroborates mask consumption in a separate caller.

The post-exit continuation reuses the two recovered comparison-record leaves, performs two further complete 624-word state twists, advances the index/counter to 130, updates additional process globals and revisits the callback gate. It stops on an unknown private read at `0x1003ECB98`, F+`0x4A0`; those bytes are not assigned source values. No new Mach/IOKit emission or transport dependency is established. The full investigation remains active.

## Provenance and assumption register

Primary specimen: `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Addresses are preferred virtual addresses. Earlier [PRNG-output](daemon_prng_output_report.md), [seed-material](daemon_seed_material_report.md), and [comparison-record](daemon_context_transfer_report.md) evidence remains frozen. [Contracts](triage_evidence/daemon_buffer_consumer_contracts.json) contain 13 source spans, seven verified original fixups, two exhaustive byte banks and 216 matching live-IDB rows, 210 distinct rows. These IDB rows do not cover every executed instruction.

| ID | Assumption or boundary | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| BC1 | The pinned image is the intended specimen | All addresses and semantics | Rehash image, source spans and original fixups; compare explicit IDB identity |
| BC2 | The frozen incoming states and startup premises apply | Whole-prefix continuations | Replay the original callback prefix before each continuation |
| BC3 | Declared API outputs/clobbers delimit the selected inputs | Numerical paths | Zero/reference tuples, two frame placements and two arena placements; arbitrary native inputs remain unknown |
| BC4 | Frame and 90,000-byte arena owners are mapped and valid | Memory operations | Fail on out-of-owner writes and undefined private reads; check the 512-byte buffer extent |
| BC5 | Readable image VM tails begin zero in the selected fresh-image model | Empty cache and initial globals | Retain loader/source provenance; native preexisting state and other writers remain unknown |
| BC6 | Known-byte/register tracking is conservative for selected instructions | Concrete continuation beyond sealed journals | Stop before using unknown register inputs; retain the unknown-read frontier and validate source opcodes |
| BC7 | Original fixups supply abstract targets; native PAC is not modeled | Indirect transfers | Verify source format-12 words, diversity, bank rules and actual abstract targets |
| BC8 | The recovered caller phase and record48 key agree | Counter equality and failure route | Source-local proofs plus all retained packet decodes; alternate phases require separate analysis |
| BC9 | The u32 array model represents aligned little-endian source accesses | Normalization formula | Lift all 112 instructions; verify address bounds, all-array semantics and isolated A64 effects |
| BC10 | Proven invariants can be composed across the sixteen updates | Idempotence | Low16 and selector invariance plus scalar idempotence; 2,192 isolated source passes |
| BC11 | Selected scheduling is retained without assuming a conventional output stream | 128+2 twists | Compare every complete 624-word state with the recovered in-place recurrence |
| BC12 | No native concurrency is represented | Store order and cache interpretation | Recover all readers/writers and synchronization; a pointer store alone is not a readiness protocol |
| BC13 | IDA reference metadata is a candidate index | Global reference census | Inspect original operands and prove one materializer; do not treat classified xrefs as direct reads/writes |
| BC14 | Post-exit numerical behavior does not establish generic caller/codec semantics | Additional calls/global values | Preserve complete packets and source write sites; recover source formulas independently |
| BC15 | Prior evidence stays frozen except six reporting/publisher paths | Preservation | Check all 3,085 prior artifacts, exactly six changes, and three original supplied inputs |

Whole-path results depend on BC1-BC8 and BC11. Normalization proofs use BC9-BC10. Lifecycle interpretations remain bounded by BC12; the global census and post-exit interpretations additionally use BC13-BC14. None establishes native reachability, concurrency behavior, object ownership or a native C++ class ABI.

## Complete loop and publication sequence

```text
sealed first two mask updates
             |
remaining 126 source updates -> 512-byte buffer, index=counter=128
             |
0x100315438: alignment and empty-cache guard
             |
0x100315478: cache pointer D in 0x1010C8268
0x100315484: store u32 255 in 0x1010C67D4
             |
sixteen word normalizations
             |
record48 equality(counter,0) -> selected nonzero continuation
             |
two further complete twists -> index=counter=130
             |
additional global writes -> callback gate -> unknown F+0x4A0 read
```

[Eight complete-prefix A64 runs](triage_evidence/daemon_buffer_consumer_profiles.json) cover the four retained F/H representations with zero/reference declared API tuples and corresponding physical backing/clobber patterns. Their verified prefixes account for 2,633,576 source visits; the new continuations add 13,734,768, totaling **16,368,344**. The new visit count includes entry into each terminal unknown-read instruction; its effects are not used for further analysis.

The compact check reconstructs all 128 buffer masks from the original mixed state and unmasked buffer. It checks 1,024 complete twist/mask checkpoints across the eight cases, including the sixteen sealed checkpoints. Each selected output is preceded by a complete twist; this scheduling is not replaced with a conventional MT19937 output stream assumption. All selected pointers remain inside their 90,000-byte owners, with 512 readable/source-defined bytes at loop entry.

| Interface | Source site | Contract |
| --- | --- | --- |
| Updated byte offset | `0x1004093FC` | Store F+`0x48C`; the final value is 512 |
| Loop guard | `0x100409418` | Unsigned updated offset <512 continues; false selects `0x100315438` |
| Buffer pointer read | `0x100315450` | Read D through `0x1010C8278` |
| Alignment test | `0x100315454..0x10031546C` | Under the source phase, require `(D&3)==0` |
| Cache test | `0x100315470..0x100315474` | Require u64 `*(0x1010C8268)==0` |
| Cache publication | `0x100315478` | Write u64 D to `0x1010C8268` |
| Constant word publication | `0x100315484` | Write u32 255 to `0x1010C67D4` |
| State-index snapshot | `0x100315688..0x10031568C` | Read `0x1010C67DC` and save u32 at F+`0x4DC` |
| Generation-counter read | `0x100315690` | Read u32 at `0x1010C8258` |

The cache pointer is stored before the sixteen word rewrites. The 255 store also precedes them. Native reader synchronization and the lifetime/replacement rules for both buffer pointer cells remain unknown. The alignment/cache checks alone do not establish buffer size, validity or a complete NULL/allocation contract.

The alignment-failure and occupied-cache paths converge at `0x100315764`. Under the recovered phase, they store raw u32 `0x74C29DEE` through F+`0x28` and select index `0x1BCB`, slot `0x101047D48`, target `0x1002DB828`, IA diversity `0x6DA3`. The semantic error name, native cleanup and failure reachability are unknown. The eight whole-prefix cases use aligned nonnull owners and empty caches; this failure contract is source-local.

## Sixteen-word normalization contract

Let `W[i]` be the little-endian u32 at D+4*i at normalization entry, after all 128 masks. For j=0..15, the source rewrites word index 4*j:

```text
u = initial_W[4*j]
k = 2*((u >> 1) & 31)                # even word index 0..62
W[4*j] = u OR u32((NOT initial_W[k]) << 16)
```

All other words remain unchanged. Source byte destinations are 0,16,...,240. Data-dependent lookup byte offsets are 0,8,...,248; the accessed lookup ends at byte 251. The highest destination ends at byte 243. The source therefore accesses only the first 252 bytes of the valid 512-byte buffer during this normalization.

The 112 instructions at `0x100315488..0x100315648` perform sixteen groups of seven instructions: load, shift, mask, indexed load, complement, OR, store. Actual reads use the current buffer. The source proof establishes equivalence to the initial-buffer formula above: every write preserves its low 16 bits, and only the lookup's low 16 bits affect the output. Aliasing with an earlier destination consequently does not change the formula.

The operation only sets bits, preserves every low16 half and its own selector bits, and is idempotent. The all-array source formula and low16 theorem compose with the proved scalar rule `g(g(x,t),t)=g(x,t)` and selector invariance. A direct two-sweep source SMT query returned `unknown` after 30 s; its [original query](triage_evidence/daemon_buffer_consumer_two_sweep_timeout.smt2) remains preserved. No UNSAT result is claimed for that query.

[Isolated A64 verification](triage_evidence/daemon_buffer_normalization_replays.json) covers 1,096 input arrays and two source executions per array: 2,192 passes, 245,504 source visits, 70,144 reads and 35,072 writes. It includes all 16 destination / 32 selector combinations at two 4-byte-aligned placements, plus zero, all-one, ascending, descending and deterministic hash patterns. It checks exact read/write addresses and values, unchanged other buffer bytes, preserved SP/NZCV and untouched general registers.

## Reused private records and post-exit state

The first post-normalization call at `0x100315734` uses original slot `0x10109FD20`, target `0x10041A5E0`, IA diversity `0xEC9D`. It passes R=F+`0xAF8`. The complete leaf's accessed footprint is 48 bytes and its output is at +`0x10`; the broader 64-byte snapshots retain known masks and do not establish a 64-byte object.

The caller decodes mode=0, A=zero-extended generation counter C, B=0. It therefore uses equality. Its generic source-local result is:

| C | Result index | Slot | Target / IA diversity |
| --- | --- | --- | --- |
| 0 | `0x16E5` | `0x101045618` | `0x1003188AC` / `0x2858` |
| Nonzero u32 | `0x16F4` | `0x101045690` | `0x1002924EC` / `0x2858` |

All eight paths use C=128 and take the nonzero route. The journal then retains four complete comparison-call packets per path. [Independent decoding](triage_evidence/daemon_buffer_consumer_checks.json) checks every consumed byte's known mask and the actual returned u32:

| Call site | Recovered leaf | Selected decoded comparison | Result |
| --- | --- | --- | --- |
| `0x100315734` | equality / unsigned greater-than, record48 | 128 == 0 | `0x16F4` |
| `0x100349B3C` | signed / unsigned less-than, record36 | unsigned 5119 <128 | `0x169B` |
| `0x1003C23A0` | equality / unsigned greater-than, record48 | 0 ==129 | `0x16F0` |
| `0x1003CBE04` | signed / unsigned less-than, record36 | unsigned 5119 <129 | `0x1783` |

Only the first caller is generalized by new source-local packet/composition proofs. The other three rows are decoded observations under the retained states, using the earlier complete leaf contracts. They do not establish all possible caller phases.

After the 128 masked words, the post-exit byte journals contain two more complete 624-word twist passes per case. Independent reconstruction checks all 1,248 state writes per case against the in-place recurrence. The index and counter become 129 then 130:

| Cell | First subsequent writer | Second subsequent writer |
| --- | --- | --- |
| State index `0x1010C67DC` | `0x100349A8C` | `0x1003CBD4C` |
| Generation counter `0x1010C8258` | `0x1003C2248` | `0x100247550` |

No additional write to the 512-byte buffer follows its sixteen normalizations before the retained frontier. The precise consumers/formulas of these two further generated results remain unresolved.

## Additional process globals and architectural touch points

The post-exit journal also establishes the following memory-write sites. Encoded-value meaning and native ownership remain unknown:

| Cell | Width | Source writers in execution order |
| --- | --- | --- |
| `0x1010CA2A8` | u64 | `0x10031ED5C`, then `0x1003F19DC` |
| `0x1010C6800` | u64 | `0x1003875B8`, then `0x1003F19F8` |
| `0x1010B70D8` | u64 | `0x1003F1850` |
| `0x1010B83A0` | u64 | `0x1003F18F8` |
| Callback gate `0x1010B5DE0` | u32 | `0x1002BC398`, selected single-thread CAS `0x5D96 -> 0xA94EF` |

The gate is the same cell analyzed in the earlier [frame-entry report](daemon_frame_entry_report.md). The callback subsequently reaches the earlier context-transfer entry and attempts an undefined F+`0x4A0` read at `0x1003ECB98`. The stop preserves that uncertainty rather than treating its physical backing pattern as a source definition.

An additional source materializer at `0x10008CFAC..0x10008D008` recovers the address of cache cell `0x1010C8268`. Its source pool base is `0x1010A1960`; encoded bank-pointer cells are `0x1010A2FB8` and `0x1010A4000`. They decode to byte banks `0x100E99A00` and `0x100F4E390`. All 256 byte-bank inputs select pool index `0x796`, slot `0x1010A5610`. Its original decoded rebase target `0x13203F54E` plus signed bias `-0x30F772E6` yields `0x1010C8268`, placed in X6 at `0x10008D004`.

The proof covers every u32 input through 256 low-byte cases with a symbolic upper 24 bits. This establishes address materialization, not a direct read/write of the cached buffer at the table-load instruction.

[The IDA reference census](triage_evidence/daemon_buffer_globals_live_ida.json) returns 24 candidates for `0x1010C8268` and zero for `0x1010C67D4` in its function/xref scope. Its operand-role fields are partial: the sampled `0x10008CFF8` is a pool-table LDR followed by address decoding, despite write/read-write classifications in the metadata. Conversely, the dynamically verified `0x1010C67D4` store is absent from that census. These counts are not a complete reader/writer census.

## Verification, preservation and limits

[Independent checks](triage_evidence/daemon_buffer_consumer_checks.json) cover the pinned source, seven original fixups, 512 exhaustive bank inputs, all 15 original/normalized SMT pairs, complete mask states, the post-exit state journals, all 32 comparison packets and one fresh complete-prefix A64 continuation. The [proof artifact](triage_evidence/daemon_buffer_consumer_proofs.json) retains three satisfiable premise witnesses and the timeout/composition distinction. [Preservation](triage_evidence/daemon_buffer_consumer_preservation.json) and [scoped delivery gates](triage_evidence/daemon_buffer_consumer_quality_gates.json) retain the prior baseline and protected inputs.

The compact mask check uses O(M*N) time and O(N+M) space for M=128 words and N=624 state words. Normalization uses O(16) time and O(1) extra mutable state; the immutable reference uses O(128) words. Full-path tooling scales with prefix/journal bytes, source visits and memory events; the new source pool has 1,905 distinct instructions. Solver queries are bounded to 30 s. These are bounded software observations, not timing measurements or native API execution.

No new import/API summary is introduced. No native Mach message, IOKit request, entropy/clock call, pointer authentication or IDB mutation executes. A shared process-local table/cache interpretation is supported by the publication and independently proved address materializer. Equating this buffer with driver payloads, cryptographic key material, a native class or a wire record is unsupported.

## Bounded continuation opportunities

| Impact | Investigation | Discriminating evidence |
| --- | --- | --- |
| High | Recover the two post-buffer generated-result consumers and global codecs | Follow frame F+0x5A0/+0x358 and writes to the four additional global cells; prove source formulas |
| High | Resolve the F+0x4A0 frontier and callback revisit | Recover its earlier writer or retain copy provenance through unknown bytes without using backing bits as definitions |
| High | Census readers/writers of both buffer-pointer cells | Decode all 24 reference candidates and other indirect aliases; establish native lifecycle and synchronization |
| High | Connect process-local state to established daemon IPC/IOKit arguments | Actual def-use paths into port/message/user-client fields, not address/name similarity |
| Medium | Expand reader/lifetime coverage of u32 mask255 at0x1010C67D4 | The cache-codec continuation establishes one mask consumer; recover other readers, bounds and initialization continuity. |
| Medium | Exercise occupied-cache, misalignment, nonzero initial counter and wrap states | Source-preserving controlled input domains and explicit reachability/ownership premises |
| Low | Use the normalization rule as a semantic search pattern | Matching source operations and independent equivalence, not constant-only matches |

## Scoped quality gates

| Gate | Result |
| --- | --- |
| QG1 | Pass: factual technical analysis |
| QG2 | Pass: BC1-BC15 with dependencies and falsification probes |
| QG3 | Pass for this increment: complete mask loop, publication, normalization, comparison caller, subsequent journals and reader materializer; full objective active |
| QG4 | Pass: u32/u64, byte offsets, little-endian memory, 128*4=512 bytes,624*4=2,496 bytes and bounded software counts explicit |
| QG5 | Pass: selected/static/native coverage, pointer stores/readiness, reference metadata/accesses, unknown bytes/backing bits and timeout/composition distinguished |
| QG6 | Pass: original source/fixups, IDB bytes, original/normalized SMT, independent compact checks and A64 replays |
| QG7 | Pass: bounded impact-labeled continuation table |

Full-goal completion is false.
