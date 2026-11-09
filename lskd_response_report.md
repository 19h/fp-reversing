# Prospective response staging and first request metadata reads

The [execution wrapper](lskd_execute_report.md) now has a checked continuation through prospective response allocation, original 160-byte clearing, a second workspace record, a stack-displacement bridge and request metadata access. The first request read checks the container header at+0; the next copies its operation word at+4 into workspace scratch storage. Valid metadata cases stop before business-request processing.

Allocation/free backends remain register-only models. Source allocation failures return `0xffff5964`; bad/null request cases return `0xffff5966` after original error stores and cleanup-call preparation. Every checked output reference remains unchanged. The later positive publication store is identified and proved locally under explicit frame assumptions; it is not executed and successful native processing remains **unknown**. The broad objective remains active and incomplete.

[Primary contracts](triage_evidence/lskd_response_contracts.json), [retained cases](triage_evidence/lskd_response_profiles.json), [distinct fresh replays](triage_evidence/lskd_response_replays.json), [independent checks](triage_evidence/lskd_response_checks.json), [twelve source-derived proof pairs](triage_evidence/lskd_response_proofs.json), [source identity](triage_evidence/lskd_response_source_identity.json), [preservation](triage_evidence/lskd_response_preservation.json) and [scoped quality gates](triage_evidence/lskd_response_quality_gates.json) retain the evidence.

```text
prepared request -> execution header -> nonnull output-reference state
  -> IOMallocTypeImpl(160-byte stream view) [REGISTER MODEL]
       null -> original status -> auxiliary/workspace free arguments -> error
       nonnull -> original memset(candidate,0,160)
         -> source 64-byte workspace record, selector 0x3be
         -> stack-displacement bridge -> metadata getter, selector 0x6ef
              null request / header != 1 -> source error and cleanup arguments
              header == 1 -> copy request.operation32 -> STOP before business state

later, static only, if raw processing status == 0x5e561849:
  restored frame/cells -> STR candidate_pointer,[output_reference]
```

## Assumption register

| ID | Assumption / bound | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| RS1 | KC and normalized image identify the pinned build | Instructions, metadata, slots and source contracts | Rehash both; compare exact compiler envelopes/spans and original chain membership; native runtime identity is separate |
| RS2 | Private mapped storage and abstracted PAC support conditional instruction semantics | All guest replay results | Reject source escapes/unmodeled calls/unknown value reads; check each original instruction; native authentication and reachability remain unproved |
| RS3 | Allocation/free register returns and caller-register clobbers match declared models | Allocation failures, post-allocation source and cleanup preparation | Verify native allocator/view/lifetime behavior separately; no model initializes, frees or writes memory |
| RS4 | Declared request/candidate/workspace/auxiliary extents are accessible and distinct | Source clearing, records and word access | Test adjacent and separated auxiliary fixtures; recover actual allocation capacities/aliases; fixture addresses do not prove native validity |
| RS5 | Source-key lemmas qualify shared-key decoding and symbolic memory cells are distinct | Local record/metadata proofs | Re-lift original/normalized formulas and compare source epochs; no arbitrary-alias or whole-program proof follows |
| RS6 | Mutable-global fixtures are stable within a run | Dispatch and displacement-seed arithmetic | Recheck original/zero/noise fixtures and exhaustive bank rules; native concurrency remains separate |
| RS7 | Container header=1 permits this metadata accessor, without proving opcode validity | Operation-word copy and local getter status | Continue the actual business dispatcher; test semantic opcode domain separately |
| RS8 | Declared lower64 D8-D11 fixtures and register models preserve their context | Source FP saves/restores and completed error paths | Check original prologues/epilogues and final D values; upper vector halves/native backend preservation remain unproved |
| RS9 | Probe-only unknown byte reads target WZR and do not supply values to metadata logic | Original stack-probe execution | Check exact probe PCs, one-byte discarded loads and private mapped addresses; distinguish unknown poison from initialized data |
| RS10 | At positive publication, SP and relevant frame cells retain the required source values | Static status partition and output-pointer store | Establish actual successful processing return, displacement and intervening writes; current source error returns prove zero displacement only for those cases |
| RS11 | Actual provider construction inherits LR4/LF/LE assumptions | 192 constructed provider request lineages | Check each constructor-record alignment and source pointer lineage; new local field-key identities have no alignment premise |

RS1-RS11 qualify corresponding claims. Retained/fresh equality shares the engine. Compact expected layouts, source formulas and independent byte-epoch reconstruction add checks without proving that engine or native model assumptions.

## Primary provenance and typed interfaces

| Item | Exact evidence |
| --- | --- |
| Original KC SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| New extraction | Eight compiler envelopes, eighteen spans, eighteen new exhaustive rules, ten bank-pointer roots, twelve state slots and two original stack helpers |
| Response allocation preparation | `0xfffffe000a524868` -> exact `_IOMallocTypeImpl`, `0xfffffe000c4ba154`; X0=view `0xfffffe000847ae60` |
| Error-path response free preparation | `0xfffffe000a5356d8` -> exact `_IOFreeTypeImpl`, `0xfffffe000c4ba368`; X0=view `0xfffffe000847b020`, X1=candidate pointer |
| Source clear | `0xfffffe000a5617b4` -> `_kernel_memset`, `0xfffffe000a508cec`, through original stub/slot to `_memset`, `0xfffffe000c648170` |

The allocation and free views are distinct addresses with identical original 64-byte contents: `site.LSKDDispatchStream`, flags word0x64, metadata size160, first16 runtime-link bytes zero. They also match the earlier request-constructor descriptor contents. This establishes source metadata and ABI operands, not runtime zone/view initialization or native object capacity.

A declared null response-allocation return selects state0x9a2 -> shared return `0xfffffe000a510628`. Source stores raw status `0x5e5571ad`; the wrapper prepares auxiliary/workspace frees and returns `u32(raw-0x5e561849)=0xffff5964`. The request is not read on this path and the output reference retains its source-zero or prior-sentinel contents.

A declared nonnull return selects state0x99c -> `0xfffffe000a561738`. Original kernel memset writes all160 candidate bytes to zero. That zeroed candidate has header word0; no checked path initializes it as a valid header1 stream. Later business processing/initialization remains unknown.

## Source 64-byte workspace record and bridge

Let R denote the second record at workspace+0x40, B=workspace+0x80, A=auxiliary allocation and C=the prospective response. Original source creates:

| Record offset | Width, bytes | Value before inner processing |
| --- | ---: | --- |
| +0x00 | 8 | B |
| +0x08 | 8 | A |
| +0x10 | 8 | workspace+0x4000 |
| +0x18 | 4 | Encoded selector; decoder recovers0x3be |
| +0x1c | 4 | Unwritten / unknown |
| +0x20 | 8 | Request pointer |
| +0x28 | 8 | C |
| +0x30 | 8 | A+0x1000 |
| +0x38 | 4 | Raw status, unwritten until inner return |
| +0x3c | 4 | Unwritten / unknown |

The source also saves C into the dispatcher frame at SP+0x28, replacing its earlier auxiliary-end value. This frame slot later supplies the conditional publication/free pointer. The output-reference address was saved at SP+8 before allocation. Neither source assignment publishes an output object.

Call `0xfffffe000a5618c0` forwards `(X0=R,X1=&displacement_cell)` to unnamed bridge `0xfffffe000a58a1c0`. It derives a 16..256-byte local stack extent from `u64(seed*0x2ec5+1)`, runs exact original `___chkstk_darwin` / `___chkstk_darwin_probe`, and calls unnamed `0xfffffe000a570f0c` at `0xfffffe000a58a3b8`. Exact import slot `0xfffffe000847c610`, helper bytes and caller state are retained.

| Bridge / inner interface | Source contract |
| --- | --- |
| Probe extent | `(((u64(seed*0x2ec5+1) >> 56) & 0xf0) + 0x10)` bytes, multiple of16 |
| Local displacement state | Initialize to `seed-0xd0`; inner prologue adds0xd0 |
| Returned caller displacement | `16 * u16(local_word32 - seed32)`, stored in an eight-byte caller cell |
| Caller use | Add that displacement to SP before reading status/frame cells |
| Checked error returns | Local state equals the initial seed; returned displacement=0 |

The roundtrip proof is local arithmetic. Later business code may change displacement state; successful processing is not covered. Original unsigned guards compare `[B+0x140,workspace+0x4000]` and `[A+0xc0,A+0x1000]`. They perform no arena initialization. The source fixes A and B independently; separated auxiliary fixtures test that no adjacency relation is required in these checked paths.

## First container reads and metadata getter ABI

The inner prefix decodes selector0x3be. A null request selects shared return `0xfffffe000a52e4b0`. A nonnull request selects `0xfffffe000a51bdec`, which creates a separate 24-byte getter record at workspace+0xa8. Call `0xfffffe000a51beb8` forwards that record in X0 to unnamed accessor `0xfffffe000a54f50c`.

| Getter record offset | Width, bytes | Meaning |
| --- | ---: | --- |
| +0 | 4 | Address-keyed selector; decoded value0x6ef |
| +4 | 4 | Source-written raw status |
| +8 | 8 | Request pointer |
| +0x10 | 8 | U32 output pointer, workspace+0x118 in these source callers |

The recovered contract applies to the source-produced selector0x6ef context; other selectors of this entry remain unknown. The selector0x3be inner record likewise scopes the checked inner prefix.

The accessor requires nonnull request and word-output pointers. It then reads the request's native u32 container header, requiring1. That word is distinct from the compact packet's big-endian tag/length header. With header1 it copies the native u32 operation at request+4 to the word-output pointer and stores raw success `0x5e561849` in getter-record+4. Rejection stores `0x5e5571af`. X0 remains the record pointer; a return-register success status is not inferred.

| Data-flow site | Original effect |
| --- | --- |
| `0xfffffe000a56b454` | Read request header word at+0 |
| `0xfffffe000a53533c` | Read request operation word at+4 |
| `0xfffffe000a535340` | Store that word into workspace scratch |
| `0xfffffe000a54f248` | Store getter raw status at record+4 |
| `0xfffffe000a51bee0` | Checked stop before metadata-success transfer to `0xfffffe000a59bf78` |

Actual provider operations0x1b69,0x1b6b,0x1b6a,0x1b6c reach this word copy. Standalone header1 fixtures also copy0,1 and0xffffffff. This establishes accessor behavior, not validity or acceptance of those operations by later business processing. Packet payload/context/pointer-span contents are not consumed by this accessor. Original request bytes remain unchanged.

Invalid headers0,2,0xffffffff read only the header and skip the operation read. Null requests skip both reads. These source errors return through the inner record and zero-displacement bridge, prepare a response free followed by auxiliary and aligned-workspace frees, then return `0xffff5966`. No backend free executes. Source preserves the lower64 bits of the declared D8-D11 contexts along these checked paths; no upper-vector or native-backend preservation claim follows.

## Conditional positive publication: static/local proof only

After the bridge returns, original caller code at `0xfffffe000a5618c4..0xfffffe000a5618d0` applies its displacement to SP before loading status/frame cells. At `0xfffffe000a5618d4..0xfffffe000a56190c`, raw inner status equal to `0x5e561849` selects state0x38c; other status selects0x3a8.

| Result state | Original target | Local effect |
| --- | --- | --- |
| 0x38c | `0xfffffe000a522e38` | Load output reference from SP+8 and prospective stream from SP+0x28; publish with STR at `0xfffffe000a522e44` |
| 0x3a8 | `0xfffffe000a535640` | Prepare typed free of the prospective stream, then shared return |

The positive store's local proof establishes full64 pointer forwarding **given the required frame cells**. It does not establish that business processing returns success, preserves those cells or yields a valid stream. The preceding source assignments establish their prepared values; checked error returns demonstrate zero displacement only on their own paths. No positive-publication instruction executes in this increment. No response object is published by any checked case.

The failure free descriptor at `0xfffffe000847b020` has the same original contents as the allocation descriptor at `0xfffffe000847ae60`; native runtime links/ownership remain unknown. The source prepares this free before the auxiliary and workspace frees. Register clobbers leave the callee-saved error status available for the wrapper's original subtraction.

## Verification and bounded continuation

| Fresh evidence | Count |
| --- | ---: |
| Cases / source visits / instruction bytes | 288 / 725748 / 2902992 |
| Read / source-write epochs | 140100 / 72804 |
| Discarded WZR probe-read epochs | 192 |
| Register-only models / model memory writes | 1392 / 0 |
| Constructed provider request lineages / packet bytes preserved | 192 / 5568 |
| Original response-clear bytes | 30720 |
| Second-record compositions / seed adjustments | 192 / 192 |
| Request header reads / operation-word copies | 180 / 144 |
| Metadata-success stops / source outer error returns | 144 / 144 |
| Null response allocations / bad headers / null requests | 96 / 36 / 12 |
| Zero-displacement error returns / prepared free calls | 48 / 336 |
| Lower64 FP contexts preserved | 288 |

The byte accounting is `192*160=30720` original candidate-clear bytes. All192 provider lineages retain complete source-built requests; output references preserve source zero or the declared sentinel. Adjacent and separated auxiliary extents remain untouched in all288 cases. Every source read/write/snapshot epoch is reconstructed, including explicitly discarded unknown probe reads. Poison0xa5 is not treated as initialized data. Completed wrapper returns restore their source-derived wrapper-entry SP; provider continuations stop before their next caller instruction.

Twelve original/normalized SMT pairs lift145 instruction instances across sixteen slices: allocation partition, record-key agreement, encoded/decoded fields, getter key/record/word copy, header gate, probe-size bounds, displacement formula, seed adjustment, result partition and conditional pointer store. Some slices overlap;145 is a lift-instance count. The decoded record uses a shared key only after source-key equality. The publication proof remains conditional as RS10 specifies.

Fresh checks cover82 exhaustive rule checks/20992 byte inputs, including predecessor rechecks. Those counts do not denote distinct permutation families. Complexity is `O(B+C*(V+E)+256R+I)` for source bytes B, cases C, visits V, events E, rule checks R and lifted instructions I, plus solver-dependent cost. Guest runs are bounded at30000 visits; each solver at30 s.

```sh
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_response.py
```

| Impact | Remaining interface question | Discriminating evidence |
| --- | --- | --- |
| High | How does business state `0xfffffe000a59bf78` consume operation, packet fields and embedded pointers? | Trace actual field reads and operation-dependent interfaces without equating metadata success with command acceptance |
| High | What initializes the candidate stream to header1 and populates it? | Original response writers and actual status/output lineage; zeroing/type metadata are insufficient |
| High | Does a real successful return preserve the frame/cells used at publication? | Follow displacement/state writes through business processing and verify actual reaching definitions at `0xfffffe000a522e44` |
| High | Does any resulting stream reach daemon IPC? | Concrete transport emission and receiver linkage; no additional Mach port or emission is established here |
| Medium | Are native allocation, lifetime, register and serialization assumptions satisfied? | Runtime view/zone state and actual backend contracts; private source fixtures remain conditional |

QG1 passes for factual technical analysis. QG2 is RS1-RS11 with dependencies and falsification probes. QG3 passes for staging, first metadata reads, original errors, displacement context and conditional publication; the broader objective remains incomplete. QG4 covers widths, byte epochs, arithmetic, counts and complexity. QG5 separates container/packet headers, metadata/operation acceptance, unknown probe/source data, register models/source status, adjacent/separated regions and local/static/native claims. QG6 uses primary bytes, exact slots, 288 fresh cases and twelve source-derived proof pairs. QG7 is the impact-labeled continuation table. Original inputs, IDBs, external dump.md and all published predecessors remain preserved.
