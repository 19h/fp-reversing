# FPHashTable initializer: size protocol, backing array and completion

The shared-table initializer at `0xfffffe000a627400`, for the recovered request token 0xabd, requests 3072 B of `site.FPHashTableEntry` storage and initializes 128 entries with a 24 B stride. It writes the returned buffer pointer into the 16 B table header at +8. A null buffer selects raw output32 `0x7cb49d7a`; a nonnull buffer selects `0x7cb541a6` after the initialization loop. This supplies the success word used by the preceding cleanup bootstrap's publication gate. Ordinary return additionally requires the stack guard to match and authenticated return to succeed. [HI1-HI8; HI-A1-HI-A8]

The entry stores are exact raw defaults: u32 `0x629f8775` at +0, u64 `0x1ee45f68039f9913` at +8, and u64 zero at +16. Bytes +4..+7 receive no store in this loop. Their previous contents remain unspecified. The defaults do not establish application key/value, UID, task or Mach-port semantics. Full table processing and a native fairplayd-kext transaction remain unknown. [HI5-HI8; HI-A4-HI-A8]

Primary evidence: [source/functions/fixups/types](triage_evidence/userclient_hash_table_initializer_checks.json.zst), [source queries and synthetic array replay](triage_evidence/userclient_hash_table_initializer_audit.json.zst), [extractor](triage_evidence/recover_userclient_hash_table_initializer.py), [auditor](triage_evidence/audit_userclient_hash_table_initializer.py), [publication verifier](triage_evidence/verify_userclient_hash_table_initializer_publication.py). Context: [shared-table bootstrap](userclient_hash_table_bootstrap_report.md), [per-client node cleanup](userclient_uidlist_cleanup_report.md), [context lifecycle](userclient_context_lifecycle_report.md), [descriptor/task interfaces](context_descriptor_task_flow_report.md). Original bytes and existing receipts suffice; no new IDA access, IDB mutation, native allocator call or target execution is performed.

```text
valid token0xabd request -> header {word0=0, word4=128}
  -> encoded size request -> decoded count128 -> 24*128 = 3072 B
  -> _IOMallocTypeVarImpl(descriptor, 3072)
     null -> header.buffer=0 -> output32=0x7cb49d7a
     nonnull -> header.buffer=P -> 128 entry initializations
                                  -> output32=0x7cb541a6
  -> compare saved/fresh stack guard
     equal -> restore frame/registers -> authenticated return
     unequal -> ___stack_chk_fail call
```

The 128-entry contiguous-array interpretation requires the no-retag condition below. The alternate pointer-retag effect is separately recovered; it is not silently included in that interpretation. Output status is a memory word in the caller's record, not a W0 return value. [HI4-HI8; HI-A2-HI-A6]

## Source and proof coverage

| Evidence | Verified scope |
| --- | --- |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original collection SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Complete functions | Initializer: 275 instructions; size helper: 126; kernel variable-allocation adapter: 6; total 407 instructions / 1628 B |
| Source models | 23 spans, 386 distinct non-transfer instructions / 1544 B; 13 transfers / 52 B retained separately; remaining 8 instructions are BTI/PAC entry/landing instructions |
| Original static data | Eight 256 B arrays; seven bank rules / 1792 byte-input cases; eight pool pointers; seven branch pointers; one variable-type descriptor and stack guard/failure bindings |
| New source obligations | 21 nonvacuous UNSAT queries; 1594 instruction instances across composed obligations; every selected source PC covered |
| Separate finite replay | 3456 source instruction instances for 128 loop iterations; 2560 written bytes checked; 512 padding bytes preserved |
| Predecessor checks | Three source queries re-solved: caller/header codec join, output publication gate and allocated-pointer publication |
| Altered evidence | Four rejections: instruction byte, bank byte, entry-size word and branch target |
| Checks decoded SHA-256 | `8daa704b136cfeb42d21efad5360e4eb7d15fceb2c4a44f4490c9706017c37f7` |
| Audit decoded SHA-256 | `74cda9ca05f63296fa580560ee0ca6ae1f836e9934dbca2a694258124a3fdb57` |

The finite replay is synthetic source interpretation against a private host byte array. It corroborates the universal single-iteration equations and loop count; it is not a native allocation or execution trace. Its nonzero initial pattern exposes padding preservation rather than assuming zero-filled storage. [HI5,HI6; HI-A4,HI-A5]

## Exact source interfaces

| Evidence | Original source location | Recovered role |
| --- | --- | --- |
| HI1 | `0xfffffe000a62750c..0xfffffe000a627560` | Valid request token 0xabd, allocated header pointer and stores of 0/128 |
| HI2 | `0xfffffe000a6275ac`; `0xfffffe000a6275c4`; `0xfffffe000a6275f0`; call `0xfffffe000a627670` | Encode private size request; call `0xfffffe000a5b3dc8` with X0=SP+0x10, IA modifier 0x2502 |
| HI3 | `0xfffffe000a5b3e68`; `0xfffffe000a5b3e94`; `0xfffffe000a5b3e9c`; `0xfffffe000a5b3fa0`; `0xfffffe000a5b3fb4` | Decode count/token, test multiply overflow, encode/clamp size and store output at request+0x20 |
| HI4 | `0xfffffe000a6276ec`; `0xfffffe000a6276f0`; `0xfffffe000a6276f4`; call `0xfffffe000a6276fc` | Variable descriptor in X0, decoded byte count in X1, exact allocator target and IA modifier 0x3ff2 |
| HI5 | `0xfffffe000a627700`; `0xfffffe000a627730`; `0xfffffe000a627774` | Store buffer pointer in header+8; null/nonzero dispatch; first loop iteration |
| HI6 | `0xfffffe000a627790`; `0xfffffe000a6277a4`; `0xfffffe000a6277b4`; `0xfffffe000a6277c8`; `0xfffffe000a6277f0` | 24 B address stride, retag guard, three field stores and loop continuation |
| HI7 | `0xfffffe000a627734`; `0xfffffe000a627778`; `0xfffffe000a62780c` | Raw failure/success words and caller-record output store |
| HI8 | `0xfffffe000a627820`; `0xfffffe000a627824`; `0xfffffe000a627828`; `0xfffffe000a627844`; `0xfffffe000a627848` | Saved/fresh canary comparison, ordinary epilogue/RETAB and stack-failure call |

The initializer's 0xa0 B frame separates saved request pointer at SP+0, a 40 B size record at SP+0x10..+0x37, stack guard at SP+0x38 and six saved register pairs at SP+0x40..+0x9f. The leaf size helper subtracts 0x10 B from SP and restores it before RET. Frame restoration is source-proved under unchanged saved-cell premises. [HI2,HI3,HI8; HI-A2,HI-A3]

## Encoded size-record contract

The initializer and size calculator implement different-looking address-dependent codecs. Their original u64 pre-multiply keys are proved equal, then substituted by congruence through the common multiplication and decoder. The receipt records that rewrite explicitly. The current request decodes to dimensionless count N=128 and internal token 0xed1. Neither token is classified as an external IOKit selector. [HI2,HI3; HI-A1-HI-A3]

| Size record field | Width | Source role |
| --- | --- | --- |
| +0 | 8 B | Caller writes a keyed word; this helper does not consume it |
| +8 | 8 B | Encoded count input |
| +0x10 | 4 B | Encoded internal token; current caller decodes to 0xed1 |
| +0x14 | 4 B | No selected producer store or helper read |
| +0x18 | 8 B | Caller writes a keyed word; this helper does not consume it |
| +0x20 | 8 B | Encoded output word Y |

For the recovered token0xed1 protocol, define unsigned u64 normalization:

```text
D = (Y + 0xdf0fb929498f8c2b) mod 2^64

D = 24*N bytes,          if N <= floor((2^63 - 1)/24)
D = 0x8000000000000000,  otherwise
```

The second value is a raw failure sentinel, not a byte-count interpretation. The unsigned multiplication-overflow gate first tests `N > floor((2^64-1)/24)` using UMULH. For the remaining counts, the signed-size test selects the encoded size only when the product is nonnegative as an i64. The composed all-u64 query proves the closed form from those source contracts. The successful encoded word is `(24*N + 0x20f046d6b67073d5) mod 2^64`; failure stores `0xa0f046d6b67073d5`. No errno or undocumented application status is assigned to these words. [HI3; HI-A3,HI-A7]

| Exact quantity | Value |
| --- | --- |
| Largest N admitted by the signed-size protocol | 384307168202282325 |
| Largest N without unsigned u64 multiply overflow | 768614336404564650 |
| Current caller | `128 * 24 B = 3072 B` |
| Typed header plus requested element bytes | `16 B + 3072 B = 3088 B`, using the preceding header-allocation contract |

These are exact integer calculations. Requested type bytes are not an allocator footprint or observed retired/allocated memory. The generic helper's failure sentinel is not claimed to reach a native allocator for another caller. [HI2-HI4; HI-A3,HI-A7]

## Variable allocation ABI and type metadata

| Channel | Original binding / value |
| --- | --- |
| Size-helper pointer | Table index 0xf7a, slot `0xfffffe000847aaf0` -> `0xfffffe000a5b3dc8` |
| Variable-allocation pointer | Table index 0xf35, slot `0xfffffe000847a8c8` -> exact `_IOMallocTypeVarImpl` at `0xfffffe000c4ba95c` |
| Variable descriptor pointer | Pool index 0x12e, slot `0xfffffe0008472870`, bias -12 -> `0xfffffe000ccc3720` |
| Kext call X0/X1 | Descriptor `0xfffffe000ccc3720` / byte count 3072 |
| Kernel adapter | X0 becomes descriptor OR 1; X1 stays 3072; W2=0x1f1004; X3=0; tail branch to `0xfffffe000bcfe5b8` |

The 64 B variable descriptor has raw word0=1, word+4=24, and a name pointer at +0x10 resolving to `site.FPHashTableEntry`. It is a different metadata layout from the fixed header descriptor with flags/size at +0x28/+0x2c. The original chained name pointer, original descriptor words and normalized words are retained separately. The factor 24 is independently corroborated by helper multiplication and array stride. Lower allocator implementation/flag semantics and actual allocation success remain outside this source contract. [HI2-HI4; HI-A1,HI-A3]

## Array fields, pointer adjustment and loop

| Entry offset | Store width | Original default |
| --- | --- | --- |
| +0 | 4 B | u32 0x629f8775 |
| +4 | 4 B | Unwritten; prior bytes preserved by this loop |
| +8 | 8 B | u64 0x1ee45f68039f9913 |
| +16 | 8 B | u64 zero |

For current index i, source computes `a=P+24*i` modulo u64, then tests `(P XOR a) AND 0xffc0000000000000`. Zero selects the normal store address a. Nonzero executes MOVK to replace a's top 16 bits with 0xc8a2. The alternate effect is proved as a raw address transformation; no native reachability or valid dereference is inferred for that branch. [HI6; HI-A4,HI-A5]

The contiguous-array contract assumes P is nonnull, the 3072 B extent does not wrap, and P and P+3071 have equal bits under mask 0xffc0000000000000. The universal index proof then shows that every i in [0,127] takes the no-retag path. The loop stores three fields, increments i by one and repeats while the new index is less than 128. Thus exactly 128 entries are visited, the final index is 128, and output dispatch follows. The first and last entry starts are P and P+3048; the final written byte is P+3071. [HI5,HI6; HI-A4,HI-A5]

Per entry, `4+8+8=20 B` are written and 4 B remain unspecified. Across the array, `128*20=2560 B` are written and `128*4=512 B` remain untouched. Source step equations establish the general store addresses/values; the 128-iteration host replay checks all entries against initially nonzero bytes. Loop time is O(128), or O(n) for the modeled iteration protocol, and additional traversal state is O(1), excluding allocator costs and audit receipts. [HI6; HI-A4,HI-A5]

| Dispatch purpose | Index / original slot | Target / IA diversity |
| --- | --- | --- |
| Size multiply, no unsigned overflow | 0xed1 / `0xfffffe000847a5a8` | `0xfffffe000a5b3f28` / 0x9933 |
| Size overflow output | 0xed9 / `0xfffffe000847a5e8` | `0xfffffe000a5b3fb0` / 0x9933 |
| Size encoded/clamped output | 0x78e / `0xfffffe0008476b90` | `0xfffffe000a5b3fb0` / 0xe9eb |
| Nonnull buffer, loop setup | 0xabd / `0xfffffe0008478508` | `0xfffffe000a627744` / 0x869c |
| Null buffer, failure output | 0xad0 / `0xfffffe00084785a0` | `0xfffffe000a627804` / 0x869c |
| Initialize next entry | 0x41d / `0xfffffe0008475008` | `0xfffffe000a627788` / 0x616e |
| Completed loop, success output | 0x436 / `0xfffffe00084750d0` | `0xfffffe000a627804` / 0x616e |

## Status, return environment and IPC relation

The source stores header+8 before testing null. Null selects raw record output32 0x7cb49d7a. The nonnull path uses 0x7cb541a6 in loop setup and every continuation, then writes it through the saved original record pointer. Three predecessor rechecks join that word to the cleanup caller's exact comparison and conditional global-header publication. Later table processing and synchronization remain separate frontiers. [HI4-HI8; HI-A3-HI-A8]

The stack guard pointer slot `0xfffffe000847c5f8` resolves to exact `___stack_chk_guard` at `0xfffffe000cacb000`. The saved/fresh compare controls B.NE to the failure call. The stub at `0xfffffe000a69f294` uses slot `0xfffffe000847c478`, resolving to exact `___stack_chk_fail` at `0xfffffe000c629694`. Output is already written before this guard check, so an output word alone does not establish ordinary return. The normal epilogue restores SP and X19-X30 from the saved frame; RETAB authentication remains a premise. [HI8; HI-A1-HI-A3,HI-A6]

Mutable controller interfaces include initializer reads/writes at `0xfffffe000ccc3340` and `0xfffffe000ccc32f8`, and helper reads/writes at `0xfffffe000ccc3398` and `0xfffffe000ccc32f8`. Different source-PC controller reads conservatively admit independent values; recovered target bindings do not rely on one selected controller snapshot or on coherent global byte aliases across opaque calls. No native controller-state invariant is claimed. [HI1-HI4; HI-A1-HI-A3]

The selected outgoing calls are private size calculation, variable allocation and the conditional stack-failure path. They add allocation, buffer and return-environment context to the [Mach-port inventory](mach_ports_report.md), with no newly recovered Mach emission/import site. Entry constants are not classified as port names. [HI1-HI8; HI-A7,HI-A8]

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| HI-A1: Pinned collection, normalized source and predecessor receipts describe this build. | All original source/type/target claims | Fresh extraction and audit reconstruction check exact bytes, dependency hashes, chained words, original/normalized metadata and symbols; reject the four evidence alterations. |
| HI-A2: Records, header, array and caller/helper frames are valid disjoint nonwrapping regions with stable saved cells. | Codec/output joins, header writes, frame restore | Query premises exclude the five pinned Mach-O VM regions, selected metadata/controller/guard storage and allocator-adapter code from the returned buffer, in addition to owned-region separation; recover actual producers/lifetimes. An overlap or invalid pointer excludes composition. |
| HI-A3: Calls return normally under the expected ABI and do not modify private saved roots/header fields outside their declared effects. | Helper/allocator continuation and final state | Return cuts make X0-X18 arbitrary; output seams are explicit. Trace actual callee effects before asserting native preservation. Controller reads remain conservative independent inputs. |
| HI-A4: Nonnull buffer supplies at least the requested 3072 B and remains owned through initialization. | Array defaults and complete loop | Verify allocator/native lifetime and compare actual buffer extent; null follows its separate output path. Host replay supplies no native allocation evidence. |
| HI-A5: The contiguous array satisfies the explicit no-retag extent condition and stable capacity128. | Linear 24 B layout and 128 iterations | Symbolic address/index proof covers all i<128 under the condition; separately verify the alternate MOVK effect. A retag-triggering address does not inherit the contiguous-array conclusion. |
| HI-A6: Stack guard matches for ordinary return, and PAC transfers/return authenticate. | Normal completion versus output-only state | Compare symbolic initial/fresh guards, original failure binding and saved-register epilogue. A guard mismatch or authentication failure excludes normal return. |
| HI-A7: Internal tokens, encoded sentinel, allocator flags and entry defaults retain raw source meanings. | ABI/type/status interpretations | Follow other token producers and entry consumers before assigning undocumented key/value, errno, UID, task or port meanings. |
| HI-A8: This is the recovered caller/token protocol, not all request-token domains, table operations or native daemon-kext pairing. | Completeness and architectural join | Continue at table-processing frontier `0xfffffe000a626dc8` and establish native class/build/connection epochs before broader claims. |

## Bounded continuation

| Impact | Next source evidence | Question resolved |
| --- | --- | --- |
| High | Table-processing frontier `0xfffffe000a626dc8`, record consumers and search/update helpers | How per-client node markers select and modify the initialized entries |
| High | Consumers of entry+0/+8/+16, occupancy word and capacity | Application-independent table schema, collision/probe policy and resource ownership |
| High | Header/global-holder writers, node producers and task references | Lifetime and serialization between per-client teardown and module-global state |
| Medium | Other size-helper and initializer token producers | Which additional internal request domains share the recovered contracts |
| Medium | Native connection/build correspondence and successful traces | Whether fairplayd reaches this allocation/teardown epoch |

## Scoped quality gates

- **QG1**: Claims concern source, protocols, widths, control/data flow and evidence limits; no normative conclusion is required.
- **QG2**: HI-A1-HI-A8 specify assumptions, dependent results and falsification probes, including allocator effects, pointer retagging, canary and caller domain.
- **QG3**: The size request/decoder, generic size guard/clamp/output, exact 3072 B allocation ABI, header buffer store, null/success paths, entry loop, status output and return environment are covered. Table processing and the full interaction goal remain active.
- **QG4**: `407*4=1628 B`, partitioned into `386*4=1544 B`, `13*4=52 B` and `8*4=32 B`. Array and type-byte calculations are exact above. Extraction costs O(B+I+256R) time/space; audit construction costs O(I+256R+128*entry bytes+query DAG), with separate SMT search and 30 s/query limits.
- **QG5**: Requested bytes versus allocator footprint, encoded sentinel versus byte count, default stores versus padding, raw retag effect versus valid contiguous layout, output word versus ordinary return, and recovered protocol versus arbitrary tokens remain distinct.
- **QG6**: Original function bytes, chained metadata, exact symbols, 21 reconstructed source queries with explicit composition/codec certificates, three predecessor rechecks, 1792 bank cases, full array replay and four evidence rejections supply scoped provenance.
- **QG7**: Ranked continuation identifies table processing/schema, ownership/lifetime, other protocol callers and native correspondence without treating this constructor contract as a complete teardown or daemon transaction.


## Shared-table lookup follow-up

The [lookup contract](userclient_hash_table_lookup_report.md) joins both cleanup records to the same token0x541 helper, classifies raw empty/tombstone/occupied states, recovers the masked-key/linear-probe policy and distinguishes candidate success from an occupied-key hit. It establishes the status/flag/index channels and conditional entry+16 read; update/removal, payload ownership, native serialization and daemon-kext pairing remain unknown. No new Mach-port emission site is established.


## Shared-table reclamation and payload-free follow-up

The [reclamation contract](userclient_hash_table_reclamation_report.md) joins cleanup to the token0xc28 entry writer and token0x559 backward scan, establishes exact counter/state/key/payload transitions, and recovers the status/nonzero-payload gate for a 120 B `site.FPSecureTunnel` typed-free request. Native allocation identity, ownership, serialization and daemon-kext pairing remain unknown. No new Mach-port emission site is established.
