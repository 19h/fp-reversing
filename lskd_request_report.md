# LSKDDispatchStream construction and provider request lineage

The carrier used by the [compact 64-bit appender](legacy_tlv_report.md) now has source construction provenance. Its original allocation descriptor is named `site.LSKDDispatchStream`, with metadata size 160 bytes. Original initialization sets header 1, operation code, entry limit, byte capacity, an inline-buffer pointer and zero counters. Four actual provider callers construct this request and append tag `0x72` before their next field/execution call.

The typed heap allocator's register return/clobbers remain a declared model. Object clearing, field initialization, pointer publication and the tag append execute as original instructions in a private guest. Native allocation validity, request execution, cryptography and IPC emission remain **unknown**. The broad goal remains active and incomplete.

[Source contracts](triage_evidence/lskd_request_contracts.json), [retained prefixes](triage_evidence/lskd_request_profiles.json), [distinct fresh replays](triage_evidence/lskd_request_replays.json), [independent checks](triage_evidence/lskd_request_checks.json), [five source-derived proofs](triage_evidence/lskd_request_proofs.json) and [alignment counterexample](triage_evidence/lskd_request_alignment_counterexample.json) retain the evidence.

```text
provider method
  -> _mzRQjC7QF6ZQbBAmA(operation, entries, payload_budget, &request)
       -> original constructor record / dispatch
       -> IOMallocTypeImpl(site.LSKDDispatchStream)  [REGISTER MODEL]
       -> original kernel memset(object, 0, 160)
       -> original initializer: fields + inline buffer
            capacity <= 128 -> original success/publication
            capacity > 128  -> STOP before IOMallocData
       -> original *output_reference = object
  -> original appender(request, tag=72, opaque_context64)
       -> 00 72 00 08 || BE64(context)
       -> entry_count=1, byte_cursor=12
  -> STOP before next typed-field call or request execution
```

## Assumption register

| ID | Assumption / bound | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| LR1 | Pinned KC and normalized image describe this build | Instructions, symbols, site metadata and slots | Rehash sources and compare exact envelopes/spans/chained-pointer membership; runtime identity is separate |
| LR2 | Private mapped storage and abstracted PAC support conditional instruction semantics | All replay results | Reject source escapes/unmodeled operations; compare each visited instruction; native PAC/mappings/reachability remain unproved |
| LR3 | IOMallocTypeImpl returns the declared null/non-null pointer and preserves callee-saved registers | Allocation-failure and post-allocation source paths | Clobber caller-saved registers/NZCV; validate native allocator/view/zone initialization separately; no heap-memory initialization is modeled |
| LR4 | The constructor's local record is 8-byte aligned | Constructor encoder/decoder key agreement and dependent field compositions | Conditional proof plus unrestricted counterexample; all 162 captured constructor records are at offset8 modulo16 |
| LR5 | The symbolic stages use distinct abstract record/object cells and shared keys tied by preceding lemmas | Universal local field/selector identities | Re-lift original slices, check key lemmas and concrete byte epochs; no general pointer-alias/native-stack claim follows |
| LR6 | Declared private object/parameter extents are accessible | Original zeroing, source fields and provider guards | Recover real allocation/parameter-size/ownership contracts; 160 is a site-size word and source footprint, not observed native zone capacity |
| LR7 | Mutable-global fixtures have no concurrent modification | Table selection and protected control flow | Recheck original/zero/noise fixtures, exhaustive rules and ordered writes; native serialization remains separate |
| LR8 | The four provider prefixes stop at their declared next call | Prepared requests and next-call arguments | Follow the actual field/execution/response/cleanup implementations separately; no policy or cryptographic result is inferred |
| LR9 | Reference census covers only its stated direct-branch/exact-qword grammar | Four direct callers and metadata-only exact pointer match | Expand indirect/computed/biased references and other modules; no complete caller set follows |
| LR10 | Scratch allocation/dispatch/free bindings in the execution wrapper are static only | Exact allocator names and wrapper ABI context | Match original slots/code; the wrapper and its dispatcher never execute in these probes |

LR1-LR10 qualify the corresponding results. Retained/fresh agreement shares the engine. Independent compact object/packet construction, instruction-derived formulas and full byte-epoch reconstruction test additional properties without proving the engine or native heap model correct.

## Primary provenance and type evidence

| Source | Identity / coverage |
| --- | --- |
| Original KC | SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext | SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Current extraction | Fifteen compiler envelopes, sixteen spans, original kernel memset, twenty new bank rules and ten state slots |
| Supplied call graph | Lines71-74 corroborate the four provider helper sequences; original excerpt/hash retained in contracts |
| Delivery | [Fresh identity](triage_evidence/lskd_request_source_identity.json), [preservation](triage_evidence/lskd_request_preservation.json), [quality gates](triage_evidence/lskd_request_quality_gates.json) |

| Typed allocation item | Original value |
| --- | --- |
| View | `0xfffffe000847b160` |
| Name pointer slot | `0xfffffe000847b170` -> `site.LSKDDispatchStream` |
| Metadata flags / size words | `0x64` / `0xa0` (160 bytes) |
| First16 runtime-link bytes in file image | Zero; runtime initialization unobserved |
| Allocator call | `0xfffffe000a529be0` -> exact `_IOMallocTypeImpl`, `0xfffffe000c4ba154` |
| Source clear | `0xfffffe000a521748` -> wrapper `0xfffffe000a508cec` -> stub `0xfffffe000a69f344` -> slot `0xfffffe000847c4d0` -> exact `_memset`, `0xfffffe000c648170` |

The allocation call supplies the view in X0. Other incidental register values are not assigned allocator argument meanings. The model supplies only X0 and caller-register clobbers; original memset writes the full 160-byte extent from poisoned private storage. The native type's complete definition, allocator state, tagging and ownership remain unknown. The import stub is a checked bounded span; no absent compiler boundary is invented.

## Constructor and inline-buffer contract

The exact named wrapper `_mzRQjC7QF6ZQbBAmA` at `0xfffffe000a50c048` consumes `(W0=operation32,W1=entry_limit32,W2=payload_budget32,X3=output_reference)`. The output reference is an ordinary memory pointer, not a Mach right.

For a nonnull output reference and declared nonnull typed allocation, source clearing precedes these original field writes:

| Offset | Width / extent, bytes | Constructed value |
| --- | ---: | --- |
| `+0x00` | 4 | 1 |
| `+0x04` | 4 | operation32 |
| `+0x08` | 4 | entry_limit32 |
| `+0x0c` | 4 | `u32(payload_budget32 + 4*entry_limit32)` |
| `+0x10..+0x8f` | 128 | Zeroed inline storage |
| `+0x90` | 8 | object+`0x10` initially |
| `+0x98` | 4 | Entry count=0 |
| `+0x9c` | 4 | Byte cursor=0 |

The 128-byte inline interval ends exactly where the buffer-pointer field begins. The initializer compares the constructed u32 capacity with 128. At or below128, it completes with the inline pointer. Above128, the source reaches `_IOMallocData` / `_IOMallocData_external` at `0xfffffe000c4ba60c`, call site `0xfffffe000a560cb8`, with X0 equal to the capacity. Execution stops before this backend; no second allocation or dynamic-buffer lifecycle is modeled.

Successful inline initialization publishes the object through the caller's output reference at `0xfffffe000a53191c`, after field initialization, then returns zero. Publication is absent at the dynamic-allocation boundary. A null output reference returns `0xffff5966` without requesting typed allocation. A declared null typed-allocation result returns `0xffff5964` and leaves the output-reference contents unchanged. The standalone failure fixtures deliberately retain a prior sentinel; actual provider callers source-initialize their request output slots to zero.

All capacities here use u32 arithmetic. The field proof is modulo `2^32`; native producer bounds and overflow-free allocation requirements are not established by this arithmetic identity.

## Alignment and compositional proof boundary

The constructor emits a 32-byte partial call record with operation tag `0x6a5`. Its encoder/decoder key identity is proved under `record_address & 7 == 0`. The 28-byte initializer record carries tag `0x542`; captured initializer records are also at offset8 modulo16. Original source records and field writes connect the two stages.

The unrestricted constructor-key identity is false. A retained algebraic counterexample has record address `0xa7672f0e`, encoder key `0xc8310288` and decoder key `0x800ca44c`. No native call or memory access was performed at that address. This falsifies an unqualified all-address claim; it is not evidence of a reachable native failure.

The five local proofs cover aligned constructor key agreement, decoded constructor fields, initializer key agreement, initializer selector/object forwarding and final carrier fields. They use 169 lifted original instructions. Field proofs use shared abstract keys only after the corresponding source-key lemmas; this is a compositional proof, not a monolithic whole-program SMT model. Fresh verification re-lifts the source, checks original/normalized formulas and reevaluates the counterexample.

## Four actual provider callers

A bounded scan of 422089 aligned text words finds four direct BL callers of the 64-bit appender. The sole exact aligned qword match is linkedit metadata, not an additional native pointer caller. Indirect/biased references and other modules are outside this census.

| Provider method / entry | Appender call | Constructor operation / entries / payload budget | Constructed byte capacity |
| --- | --- | --- | ---: |
| `eJ7hqOh8Z`, `0xfffffe000a505848` | `0xfffffe000a5058b0` | `0x1b69` / 1 / 8 | 12 |
| `KDGetReEncryptionVault`, `0xfffffe000a505958` | `0xfffffe000a5059c4` | `0x1b6b` / 2 / 16 | 24 |
| `sxvHysrIgQq2V`, `0xfffffe000a505ac8` | `0xfffffe000a505b58` | `0x1b6a` / 5 / 44 | 64 |
| `ZURJElCowjwysX`, `0xfffffe000a505de0` | `0xfffffe000a505e50` | `0x1b6c` / 2 / 12 | 20 |

The compact four-byte tag/length header remains distinct from the earlier ten-byte daemon key/tag/length format. No producer-consumer equivalence is established.

These values are operation data, not established Mach message IDs. All four capacities fit the inline region. Each constructor receives a source-zeroed stack output slot; original source publishes the allocation fixture there, and a later source read of that same slot supplies the appender's X0. Every valid prefix appends tag`0x72`, length8 and the full64 context value, without dereferencing that context value. Afterward entry count=1 and byte cursor=12. Payload budget describes reserved capacity, not a proof that all reserved bytes will be populated.

| Prefix boundary | Original next call / established arguments |
| --- | --- |
| `eJ7hqOh8Z` | At `0xfffffe000a5058e0`, execute `_TdtbU9WbbSyE1sdsj(request,&response)`; response slot remains source-zeroed |
| `KDGetReEncryptionVault` | At `0xfffffe000a5059fc`, next span helper gets tag`0x8b`, pointer to an eight-byte stack representation of the original output-buffer pointer, length8 |
| `sxvHysrIgQq2V` | At `0xfffffe000a505b90`, next span helper gets tag`0x6b`, pointer to an eight-byte stack representation of the original parameter pointer, length8 |
| `ZURJElCowjwysX` | At `0xfffffe000a505e84`, next u32 helper gets tag`0x7e` and input word at parameter+`0x10` |

The next helper/execution effects are unexecuted. The pointer representations above are source arguments to an internal helper, not proof of external pointer transport or address-space interpretation.

`sxvHysrIgQq2V` rejects a null `_AVDDecryptParams` pointer with `0xffff5bd9`. Valid prefixes source-clear its qword at+`0xf0` before construction, giving a 248-byte minimum touched extent. `ZURJElCowjwysX` rejects a null parameter or first u32 word other than1 with `0xffff5966`; the valid prefix reads context64 at+8 and the next u32 at+`0x10`. This establishes request-building admission, not a decryption-permission result. Original `_FPDebugDisplayStatusMsg` zero-status paths execute quietly; no logging backend is modeled or executed.

## Execution-wrapper interfaces: static only

The exact `_TdtbU9WbbSyE1sdsj` at `0xfffffe000a50c508` is retained statically and excluded from executed ranges.

| Call site | Exact matching-KC target | Static interface evidence |
| --- | --- | --- |
| `0xfffffe000a50c6ac` | `_IOMallocAligned` / `_IOMallocAligned_external`, `0xfffffe000c4b9a08` | X0=`0x4000` (16384 bytes), X1=`0x40` (64-byte alignment) |
| `0xfffffe000a50c74c` | `_IOMallocTypeImpl`, `0xfffffe000c4ba154` | Typed-view operand; execution-context type not recovered here |
| `0xfffffe000a50c858` | Unnamed `0xfffffe000a55f5e4` | Protected dispatcher call; no request/crypto/transport semantics executed |
| `0xfffffe000a50c8f8` | `_IOFreeTypeImpl`, `0xfffffe000c4ba368` | View/object free interface |
| `0xfffffe000a50c950` | `_IOFreeAligned`, `0xfffffe000c4b9a24` | Aligned allocation pointer and size`0x4000` |

These exact original-symbol bindings resolve the older unmapped-address ambiguity. They do not establish a completed native allocation/execution/free transaction, native OOM behavior, transport choice or reference balance.

## Validation and bounded continuation

| Fresh coverage | Count |
| --- | ---: |
| Cases / source visits | 222 / 138546 |
| Instruction bytes rechecked | 554184 |
| Read epochs / source-write epochs | 26346 / 14778 |
| Aligned constructor / initializer records | 162 / 114 |
| Typed-heap register-return models | 138 |
| Original memset bytes, distinct extent summed over cases | 18240 |
| Source pointer publications | 96 |
| Inline constructor returns / dynamic-allocation stops | 48 / 18 |
| Null allocation / null output-reference returns | 24 / 24 |
| Provider compositions / provider guard returns | 48 / 60 |
| Provider tag72 bytes | 576 |
| Source-derived proofs / unrestricted counterexamples | 5 / 1 |

Original, zero and declared-noise globals, two aligned placements, the four real constructor tuples, inline-boundary sizes128/129/132, prior-output sentinels and two context values are covered. All original read bytes, source/model ordering, snapshots and publication-to-consumption epochs are independently reconstructed. No model writes object/output memory. All completed returns restore entry SP. Dynamic and provider boundaries remain explicit stops.

Complexity is `O(B+C*(V+E)+W+256R+I)` for source bytes B, cases C, visits V, events E, census words W, rule checks R and lifted instructions I, plus solver-dependent cost. Runs are bounded at30000 visits and solver calls at30 s. There are42 exhaustive rule checks (10752 byte inputs), including rechecked predecessors; these are rule checks, not42 distinct permutation families.

```sh
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_request.py
```

| Impact | Remaining interface question | Discriminating evidence |
| --- | --- | --- |
| High | What consumes the prepared LSKD stream? | Trace actual execution-frame/request lineage and dispatcher interfaces without equating them to daemon IPC |
| High | How are the next span/u32 fields represented and consumed? | Follow the captured exact arguments and source pointer representations; keep address-space meaning separate |
| High | What establishes native allocator/type-view/cursor invariants? | Native initialization/ownership evidence and actual callers; private storage and metadata do not prove it |
| Medium | How does dynamic storage complete or fail? | Continue from the exact stopped `_IOMallocData` ABI and subsequent publication/cleanup interfaces |
| Medium | Does the unresolved allocator-return store populate cached RW cell `0xfffffe000ccceab8`? | Original destination/frame/dispatcher reaching definitions; this increment adds no cached-lock publication proof |

QG1 passes for factual technical analysis. QG2 is LR1-LR10 with dependent results and falsification probes. QG3 passes for constructor, inline storage/publication, four provider prefixes and static execution-facility bindings; the broader goal remains incomplete. QG4 covers widths, byte epochs, counts, capacity arithmetic, units and complexity. QG5 separates aligned/unrestricted identities, modeled heap/source initialization, inline/dynamic, request-building/policy and static/executed interfaces. QG6 uses primary bytes/metadata, exact symbols/chains, supplied call-graph corroboration, 222 fresh cases and five source-derived proofs. QG7 is the impact-labeled continuation table. Original inputs, IDBs, external `dump.md` and published predecessors remain preserved.
