# Sample metadata, buffered/direct AES handoff and typed provider arguments

The recovered coordinator uses a raw four-byte size stream to choose buffered or descriptor-based AES submission. The buffered path gathers aligned sample prefixes into cached buffer bytes and keeps separate 16-byte XOR records in the 8192-byte workspace. The direct path passes the samples descriptor without those data reads. Original wrapper execution connects the processing-state base to the provider's `IOAESKeyData *` argument and state `+0xb0` to its `IOAESIV *` argument.

These roles follow original arguments and an exact C++ symbol. Native input validity, actual task identity, dynamic provider class, valid key-data contents, successful cryptography and post-submission processing remain unknown. No additional Mach emission or runtime IPC event is established. This extends the [state construction](sample_state_report.md), [caller records](sample_caller_report.md), [descriptor ABI](sample_descriptor_report.md) and [provider handoff](kext_aes_handoff_report.md) reports.

[Contracts](triage_evidence/sample_transfer_contracts.json), [201 transfer profiles](triage_evidence/sample_transfer_profiles.json), [103 composed wrapper profiles](triage_evidence/sample_transfer_handoff_profiles.json), [distinct fresh replays](triage_evidence/sample_transfer_replays.json), [independent checks](triage_evidence/sample_transfer_checks.json) and [eight local proofs](triage_evidence/sample_transfer_proofs.json) retain the evidence. ST1-ST8 below delimit all source/model claims.

```
size descriptor -> readBytes(index * 4, state+0xc4, 4)
                  -> u32 size S; aligned prefix A = S & 0xfffffff0

S < 16: no payload read or AES call for this element in inspected prefixes

pending batch B + S <= 8192:
  samples descriptor -- tail block --> workspace + 16 * buffered-element index
  original XOR with state IV bytes -> workspace slot
  samples descriptor -- A bytes ----> cached global buffer + B
  after collection: global-buffer wrapper -> nominal provider call [STOP]

B + S > 8192:
  B nonzero -> submit existing buffered batch [STOP]
  B zero    -> samples descriptor wrapper -> nominal provider call [STOP]

state base ------- IOAESKeyData * argument
state +0xb0 ------ IOAESIV * argument
```

This diagram describes the tested, nonwrapping arithmetic domain and prefixes ending before the first submission. It is not a complete processing algorithm, public input schema, native acceptance result or cryptographic-output validation. Descriptor/hardware/heap/copy/read effects are declared models. AES transformations and provider implementation code remain unexecuted; original XOR preprocessing runs only on synthetic inputs.

## Primary source and execution scope

| Source | Verified identity / coverage |
| --- | --- |
| Normalized kext | SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original KC | SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Original functions | Coordinator, samples bridge, two AES wrappers, two descriptor readers and hardware initializer |
| Selected targets | Six exhaustive byte-bank rules, 1536 byte inputs; original chain membership verified |
| Nominal provider | `IOAESAccelerator` vptr +`0x890`, original slot `0xfffffe0008588c10`, target `0xfffffe000abff358`, diversity `0x17dc` |
| Fresh prefixes | 201 caller cases, 205759 original instruction visits |
| Fresh compositions | 103 original bridge/wrapper cases, 3031 visits; stop before provider BLRAA |

All addresses are unslid. Only private guest instructions and explicit data/result models run. No native descriptor, task mapping, sample I/O, allocation/free, provider, crypto, IPC or IDB operation executes. The composed receiver and descriptors are nominal object fixtures, not attested native objects. PAC is abstracted. The 17 multi-sample prefixes cover two or three elements, not arbitrary stream lengths.

## Metadata stream and return-width contract

Call `0xfffffe000a625c6c` resolves to `readSampleSizesIOMD` at `0xfffffe000a509a60`. It supplies:

| Argument | Original source |
| --- | --- |
| Offset64 | `4 * zero_extend64(u32 metadata_index)` from `UBFIZ X0, X8, #2, #0x20` |
| Destination64 | State base +`0xc4` |
| Count64 | 4, zero-extended from W2 |
| Wrapper result | Full64 IOByteCount, as established in the preceding descriptor report |
| Caller test | `CMP W0, W8` at `0xfffffe000a625c8c`, expected low32 value 4 in recovered state |

Original `LDUR W8, [X3,#0xc4]` loads a zero-extended u32. There is no byte swap between the modeled four-byte read and this load. Thus the internal consumer interprets the bytes as little-endian u32 on this target; this does not establish an upstream wire encoding or producer type.

Metadata offsets 0, 4 and 8 are observed in multi-element prefixes. The general argument formation retains a 34-bit byte offset from a u32 index. Descriptor byte offsets, metadata indices and buffer offsets remain different quantities.

Read-result models include canonical 0/3/4 results and upper-width stress `0x100000004`. The latter reaches the equality branch because W0 is tested. It exceeds the requested extent and is not established as a possible native IOByteCount result. It is a local width probe, not evidence of a native defect or a usable input. Tail/bulk result probes retain the same distinction. ST3 applies.

## Block geometry and path selection

For the loaded u32 size S, the source forms A as:

```
A64 = zero_extend64(S) & 0xfffffff0
    = 16 * floor(S / 16)
```

S and A denote byte counts. `S > 15` is equivalent to `A >= 16`; the inspected prefixes perform no payload read or AES call for elements below this threshold. For a raw size 17, A is 16; later descriptor offsets still advance by the raw size 17. No claim is made about ultimate treatment of the unaligned remainder after the stopping boundary.

The source capacity comparison uses a W-register addition of the raw size and buffered byte count, followed by an unsigned comparison with 8192. The mathematical capacity interpretation assumes a nonwrapping sum; all retained cases satisfy that domain. Neither the local proof nor the fixtures establish upstream bounds or a complete safety invariant for arbitrary native streams.

| Declared raw sizes | Observed aligned bulk lengths | Observed source data offsets | First submission boundary |
| --- | --- | --- | --- |
| `[16]` | 16 | 0 | Global-buffer wrapper, length 16 |
| `[17,32]` | 16, 32 | 0, 17 | Global-buffer wrapper, length 48 |
| `[15,16]` | 16 | 15 | Global-buffer wrapper, length 16 |
| `[4096,4096]` | 4096, 4096 | 0, 4096 | Global-buffer wrapper, length 8192 |
| `[4096,4097]` | First 4096 only | 0 | Existing 4096-byte batch submitted before processing the pending element |
| `[8193]` | No buffered data read | Direct offset 0 | Samples-descriptor bridge, length 8192 |
| `[15,8193]` | No buffered data read | Direct offset 15 | Samples-descriptor bridge, length 8192 |
| `[32,16,48]` | 32, 16, 48 | 0, 32, 48 | Global-buffer wrapper, length 96 |

The descriptor path also forms `0xfffffff0` from raw size `0xffffffff` in a width fixture. This is argument formation before a stopped call, not an accepted native extent. The two nonzero-offset direct cases forward the same zero-extended saved u32 offset to both source and destination parameters.

## Separate payload and workspace counters

The buffered path has two source/model read sites:

| Site | Target | Observed argument rule |
| --- | --- | --- |
| `0xfffffe000a625f48` | `readSamplesIOMD`, `0xfffffe000a509ab0` | Offset = current raw data offset + A - 16; destination = workspace + 16 * buffered-element index; count = 16 |
| `0xfffffe000a62602c` | Same helper | Offset = current raw data offset; destination = cached global buffer + buffered aligned-byte count; count = A |

The tail and bulk models return consistent synthetic descriptor bytes at identical offsets. Those bytes are not actual sample content. Original instructions at `0xfffffe000a625f94..0xfffffe000a625fc8` XOR four 32-bit tail words with state words `+0xb0/+0xb4/+0xb8/+0xbc` and store 16 bytes into the workspace slot. The verifier independently checks the bytewise XOR and its source-write epoch before the following bulk read.

For `[32,16,48]`, workspace slots start at offsets 0, 16 and 32, while global-buffer destinations start at 0, 32 and 48. This distinguishes the per-element 16-byte workspace records from the concatenated payload length. Their complete post-AES purpose remains unproved; no CBC/output correctness is inferred merely from this XOR pattern.

Across retained cases, 90 tail reads and 88 bulk reads are modeled. Eighty-eight complete original XOR records cover 1408 source-written bytes. The two short tail reads exit before those XOR stores. Global-buffer data is marked defined only for the modeled transferred bytes. No original caller instruction reads undefined workspace or global-buffer bytes in these cases.

The cached-byte cell is `0xfffffe000ccc7848`; the global-buffer descriptor cell is the distinct `0xfffffe000ccceb10`. The initializer source stores its descriptor and derived byte pointer through these separate cells. The model seeds a private 81920-byte region and a cached-pointer fixture; the composed wrapper uses a separate nominal descriptor. Their native construction, coherence and backing-page identity are not proved. The 8192-byte batching threshold and 8192-byte workspace are not the 81920-byte backing allocation's total capacity.

## Typed IV/key-data role and provider composition

The original exact provider symbol is:

```
__ZN16IOAESAccelerator10performAESEP18IOMemoryDescriptorS1_yP7IOAESIV14IOAESOperationP12IOAESKeyDatayyPFvPviES7_
```

Its type sequence identifies descriptor pointers, length64, `IOAESIV *`, `IOAESOperation`, `IOAESKeyData *`, two u64 offsets, callback and context. This supplies primary type evidence for the pointer roles; it does not define the private structures or enum values.

| Caller boundary | Original arguments relevant to the handoff |
| --- | --- |
| `0xfffffe000a625e40` -> `0xfffffe000a509fe8`, samples bridge | `(A64, state+0xb0, byte0==0, state, offset32_zero_extended, same_offset)` |
| `0xfffffe000a626158` -> `0xfffffe000a508484`, global-buffer wrapper | `(state, state+0xb0, buffered_bytes32, raw_byte0)` |

The state base is forwarded as the opaque `IOAESKeyData *` argument. State `+0xb0`, populated from carrier `[+0x12,+0x22)`, supplies the `IOAESIV *` argument. This establishes parameter roles, not a complete `IOAESKeyData` layout, key provenance, key contents, a public packet format or a native-valid object. The raw state scalars recovered previously retain unknown field meanings.

Original bridge/wrapper execution stops before each provider call:

| Provider ABI | Descriptor path | Buffered path |
| --- | --- | --- |
| Original call site, stopped before execution | `0xfffffe000a50859c` | `0xfffffe000a5084f0` |
| X0 | Nominal provider fixture | Same provider role |
| X1 / X2 | Same samples descriptor pointer twice | Same global-buffer descriptor pointer twice |
| X3 | Full64 bridge length, caller formed from aligned u32 | Zero-extended u32 accumulated buffer length |
| X4 | State +`0xb0` | State +`0xb0` |
| W5 | Boolean `byte0 == 0` | `zero_extend32(byte0) XOR 1` |
| X6 | State base | State base |
| X7 | Zero-extended saved u32 source offset | 0 |
| SP+0 | Same destination offset | 0 |
| SP+8 / SP+16 | Callback/context 0 / 0 | Callback/context 0 / 0 |

The descriptors are separate nominal fixtures for these two paths. Equal source/destination pointer arguments are source facts; actual backing-page validity/aliasing and runtime provider overrides remain unknown. All 103 compositions preserve typed IV/key-data links and 2472 source-written stack bytes. Opaque IV/key-data pointers are not dereferenced by these wrapper runs, and provider code is never entered. ST4/ST5 apply.

## Operation argument equality depends on the input domain

The direct path uses `CSET W2, EQ` after comparing byte0 with zero. The buffered caller passes the raw byte in W3; the global wrapper applies `EOR W5, W3, #1`.

| Raw byte0 | Descriptor-path provider operation | Buffered-path provider operation |
| --- | --- | --- |
| 0 | 1 | 1 |
| 1 | 0 | 0 |
| 255 | 0 | 254 |

The local proof establishes equality of these enum argument values exactly when the u8 input is 0 or 1. Sixteen retained boundary cases have byte0 = 255 and exhibit the argument difference. Actual enum meanings, accepted operation values, upstream byte0 validation and whether higher bits affect native behavior are unknown. The result does not establish a native processing defect. ST6 applies.

## Declared results, cleanup and stopping boundaries

| Result class | Cases | Verification boundary |
| --- | --- | --- |
| Metadata/tail/bulk count mismatch | 71 | Complete modeled caller returns; encoded status `0xce515bb2` |
| No aligned payload submitted | 27 | Complete modeled caller returns; encoded marker `0x31ae0066` |
| Buffered submission | 78 | Stop before `performHWAESOnGlobalBuffer`; separate original-wrapper run stops before provider |
| Descriptor submission | 25 | Stop before `performAESonSamplesIOMD`; separate bridge/wrapper run stops before provider |

All return cases free the modeled workspace. Earlier descriptor retirement contracts remain as recorded in the state report; no native reference-count or implicit-completion effect is established. Provider results are not modeled in this increment, so none of the submission-boundary cases proves a successful AES operation or subsequent copyout/cleanup.

Six cases clobber caller-saved X1-X17 and condition flags after the metadata read model. The recovered argument links survive those declarations, independently of incidental preservation in the default read model. They do not prove arbitrary callee behavior or full reaching definitions through the original parent frames.

Read models write only the declared transferred prefix, bounded by the request. The transferred samples follow one deterministic synthetic byte function of descriptor offset, allowing tail/bulk consistency to be checked without actual sample/key content. Partial-read and upper-result fixtures remain labeled models. Neither a successful modeled read nor a recorded submission counts as native transfer or cryptographic acceptance.

## Verification and reproduction

| Check | Result |
| --- | --- |
| Original source contexts | 7 compiler-bounded functions; 36 selected instruction facts |
| Target bindings | 6 exhaustive banks, 1536 byte inputs; 1 nominal authenticated provider slot |
| Local identities | 8 unsatisfiable negated queries |
| Fresh caller prefixes | 201; 205759 original instruction visits |
| Metadata read models | 219; 707 modeled bytes; 33 upper-width metadata-result cases |
| Sample read models | 178; 207246 modeled transferred bytes |
| Tail / bulk models | 90 / 88 |
| Original XOR records | 88; 1408 source-written bytes |
| Defined global-buffer bytes | 205823 summed over cases |
| Multi-element / caller-clobber prefixes | 17 / 6 |
| Fresh composed handoffs | 103; 3031 original instruction visits |
| Provider stack epochs | 2472 source-defined bytes |
| Crypto/provider/native API operations | 0 |

The verifier re-reads original functions, exact symbols, pointer-chain metadata, bank bytes and proof files. A separate prefix classifier predicts metadata offsets, data read requests, buffering/flush choices and stopping conditions for the declared cases. Source-write epochs independently check the XOR workspace records and the provider's three stack qwords. The classifier does not extend the source capacity comparison beyond its stated nonwrapping arithmetic domain.

Time is O(C*(B+V+L)+I+E) and retained space O(B+retained cases/events), plus solver-dependent fixed-word work. C counts cases, B mapped bytes, V bounded source visits, L modeled bytes, I inspected source and E events. Caller runs have a 20000-instruction cap; composed wrappers have a 512-instruction cap. The provider-call instruction is observed before execution.

The command used before publication follows. Published outputs remain frozen; reproduction requires a separate copy and distinct output paths.

Set `PYTHON`, `Z3_PYTHONPATH` and `Z3_LIBRARY_DIR` to the analysis interpreter and matching Z3 module/library locations.

```
PYTHONPATH="triage_evidence:${Z3_PYTHONPATH}" \
Z3_LIBRARY_PATH="${Z3_LIBRARY_DIR}" \
"${PYTHON}" -P triage_evidence/validate_sample_transfer.py
```

## Assumption register and bounded continuation

| ID | Assumption / boundary | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| ST1 | Pinned original KC/normalized build and compiler bounds identify these routines | All source/slot/prototype bindings | Rehash originals; compare complete function bytes, exact symbols and chain membership |
| ST2 | Selector/frame/carrier/task/global buffer are declared fixtures | 201 source prefixes and cached-buffer data flow | Retain all input bytes, overridden cached-pointer cell and source-defined state; prove real predecessors and native pointer coherence separately |
| ST3 | Descriptor reads and returned counts are modeled, including noncanonical upper-width stress | Metadata/data branches and synthetic transfer effects | Short/exact/upper counts, partial-write prefixes and caller-saved clobbers; native count realizability remains unproved |
| ST4 | Provider, global descriptor and samples descriptor are nominal independent fixtures; PAC is abstracted | 103 original-wrapper compositions | Original class slot/type and call/frame bytes; actual provider class, authentication and receiver state require independent evidence |
| ST5 | State base and interior pointer identify argument roles, not private type layouts | IV/key-data producer links | Match the exact mangled type sequence and original moves; do not infer key contents, enum meanings, structure size or native-valid instances |
| ST6 | Upstream byte0 domain and operation-flag semantics are unknown | Conditional direct/buffered argument equality | Universal u8 identity plus concrete 255 cases; inspect validation and provider consumers before interpreting behavior |
| ST7 | Tested capacity sums do not wrap; multi-element runs end before their first AES submission | Buffering classifier, offsets and local capacity proof | Raw-versus-aligned boundary cases and source W-register arithmetic; complete native stream bounds, long-loop invariants and post-AES processing remain unproved |
| ST8 | Fake read bytes are deterministic opaque data and provider calls never execute | Original XOR records and prefix-only completion claims | Independent byte/epoch checks, definedness guards and explicit stopping sites; no native output or accepted operation inferred |

| Impact | Further work | Interface question resolved |
| --- | --- | --- |
| High | Recover byte0 producer validation and operation consumers | Whether both paths' enum values are intended to agree for every native-valid input |
| High | Trace post-submission returned status, descriptor writes and final retirement | Complete output, ownership and error-delivery contracts |
| High | Prove original parent-frame and task-carrier predecessors | Native input reachability and address-space identity |
| High | Establish actual initializer/provider/descriptor state and serialization | Runtime coherence of cached bytes, descriptor objects and global calls |
| Medium | Extend source loop invariants and validation without conflating raw/aligned/mask counts | Complete buffering limits and offset domains |
| Medium | Recover private key-data/operation definitions from matching primary metadata | Names and semantics of raw state fields without speculative structure assignments |

QG1: factual technical analysis requires no normative conclusion. QG2: ST1-ST8 retain dependent results and falsification probes. QG3: metadata, two transfer paths, counters, typed pointer/operation roles, wrapper composition and pre-provider ABI are covered for this increment; the broad goal remains active. QG4: byte extents, u32/u64 widths, arithmetic domains, source epochs and complexity are explicit. QG5: provider argument differences/native behavior, raw/aligned offsets, modeled/real counts, nominal/runtime class and pre/post operation are separated. QG6: original source/symbols/chains, eight proofs, six exhaustive banks and 304 fresh source cases support the stated scope. QG7: impact-labeled continuation is complete.

[Source identity](triage_evidence/sample_transfer_source_identity.json), [prior-artifact preservation](triage_evidence/sample_transfer_preservation.json) and [delivery quality gates](triage_evidence/sample_transfer_quality_gates.json) retain final readback.


The [shared operation preflight](lskd_operation_preflight_report.md) now binds original W1 values 1,2,4,5 to a no-op hook followed by an `initKernelAESHW()` record wrapper. Nonzero initializer low32 results enter the prior conditional return path unchanged; zero continues operation dispatch. The continuing source recovers original X2/X4-low32, saves the address of cached-byte cell CCC7848, and establishes numeric thresholds 32/16 for W1=1/5; the subsequent byte-span analysis establishes their byte units and both continuations. Native epochs, full operation meanings and daemon transport remain open.

The [operation 1/5 byte-span analysis](lskd_byte_spans_report.md) resolves original X2 as source, X3 as destination and low32(X4) as a byte count. The 32/16-byte tests select short-copy versus full-split routes; shorter counts copy unchanged and reach conditional outer zero under the prior return premises. Full-split routing copies a 16/0-byte prefix and a 0-15-byte suffix before handing an aligned middle span to A5722B8. Sixty-four bounded direction/length cases prove per-pass snapshot copying; whole-operation overlap behavior, native epochs and daemon serialization remain open.

The [middle-span hardware-staging analysis](lskd_hardware_staging_report.md) now follows A5722B8 through a 16-byte P+134 context window, working IV staging, 81920-byte capped copy chunks and `performHWAESOnBuffer`. Its nominal typed provider ABI receives key-data pointer P+184, IV at bodySP+270, numeric operation 1 and the saved total middle count; copy calls instead receive the current chunk count. The loop and conditional outer 0/-22 status paths are certified. Native descriptor bounds, provider effects, whole-operation overlap and daemon request lineage remain open.

The [descriptor-AES admission and scheduling analysis](aes_provider_admission_report.md) establishes the full64 16-byte-aligned provider length guard through 8388608 B, early key-data+24 low31 publication and optional provider-table key remapping. It connects the earlier sample-state control word to the typed provider selector, resolves descriptor physical-address requests and command fields, and distinguishes the immediate threshold from the operation-specific scheduler quantum. Descriptor extent acceptance, full key policy, native class/configuration, hardware completion and daemon linkage remain open.
