# Descriptor processing state: packed inputs, fill/copy ABI and workspace lifetime

The inspected continuation of `0xfffffe000a6247a4` builds a partial processing-state object from a separate byte-oriented carrier. It clears 168 bytes, writes a raw header word, selects control words from input bytes and copies opaque 16-/32-byte spans. It then requests an 8192-byte `IOMallocData` workspace. Declared empty-loop and allocation-failure paths retire samples and sample-size descriptors in a source-established order. Nonempty cases stop before a four-byte sample-size descriptor read.

This extends the [caller/builders report](sample_caller_report.md), [descriptor ABI](sample_descriptor_report.md) and [buffer lifecycle report](kext_buffer_report.md). The raw control codes' business meanings, ultimate task identity, valid native inputs, actual data transfer, native lifetime and successful cryptographic operation remain unknown. No new Mach emission or port-right event is established.

[Original contracts](triage_evidence/sample_state_contracts.json), [state profiles](triage_evidence/sample_state_profiles.json), [guarded fill profiles](triage_evidence/sample_state_fill_profiles.json), [distinct fresh replays](triage_evidence/sample_state_replays.json), [independent checks](triage_evidence/sample_state_checks.json) and [six local proofs](triage_evidence/sample_state_proofs.json) retain the evidence. Addresses are unslid; offsets and extents are bytes. SS1-SS8 qualify the source/model boundaries.

```
internal record +0x20 -> byte-oriented input H
internal record +0x00 -> state object O

O+0xc4 <- 0
O+[0x04,0xac) <- original zero-fill helper, 168 bytes
O+0x00 <- raw u32 0x80

H+0x01 ----> control partition ----> O+0x24 / O+0x28
H+[0x02,0x12) -- opaque 16 bytes -> O+[0x04,0x14)
H+[0x39,0x59) -- opaque 32 bytes -> O+[0x2c,0x4c)

IOMallocData(8192)
  NULL -> samples release -> sizes complete -> sizes release -> status store
  nonnull, empty loop -> IOFreeData -> same descriptor suffix -> status store
  nonnull, nonempty:
    H+[0x12,0x22) -- opaque 16 bytes -> O+[0xb0,0xc0)
    readSampleSizesIOMD(offset=0, buffer=O+0xc4, count=4) -> STOP before call
```

The arrows represent original argument formation plus explicitly modeled copies. They do not establish native pointer validity, aliasing, accepted requests or successful mapping. The workspace's bytes are not marked defined by the allocation model and are not read by these source paths.

## Source and verification coverage

| Source | Coverage |
| --- | --- |
| Normalized kext | SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original KC | SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Kext functions | Coordinator, 360-byte fill helper and 8-byte copy thunk; original/normalized equality |
| Kernel functions | Exact `IOMallocData`/`IOMallocData_external`, `IOFreeData`, and shared `memcpy`/`memmove` entry bodies |
| Bindings | Original copy stub/import slot; ten exhaustive byte-bank rules, 2560 byte inputs |
| SDK | Pinned `IOKit/IOLib.h`, compile-only arm64e allocation/free probe; `vm_size_t` is 8 bytes |
| Fresh source cases | 6104 fill cases and 1044 state cases; 1157390 total instruction visits |

Only the original fill helper and caller instructions execute in a private Unicorn guest. Descriptor/hardware results, nonoverlapping copies, workspace allocation and workspace release are models at the original call sites. No target native allocation, task access, mapping, copy API, provider operation, crypto operation, IPC action or IDB mutation executes. SDK output is assembly only. [Source identity](triage_evidence/sample_state_source_identity.json) and [preservation](triage_evidence/sample_state_preservation.json) retain final readback.

## Secondary carrier and processing-state fields

The secondary carrier is the pointer at internal record `+0x20`; it is not established as a public Mach/IOKit wire record. Its observed field positions include unaligned byte spans. A compiler-default structure layout cannot replace these offsets. SS2/SS4 apply.

| Carrier offset / interval | Width | Observed role |
| --- | --- | --- |
| `+0x01` | u8 | Direct control partition, comparisons with 1, 2 and 3 |
| `[+0x02,+0x12)` | 16 bytes | Opaque span A, copied on mode 3/default paths |
| `[+0x12,+0x22)` | 16 bytes | Opaque span C, copied at the inspected nonempty-loop boundary |
| `+0x2c` | u32 | Earlier setup-control word, zero in current fixtures; preceding report covers its nonzero unwind |
| `+0x38` | u8 | Default-path companion control: zero versus nonzero |
| `[+0x39,+0x59)` | 32 bytes | Opaque span B, copied on selected paths |

The maximum copied source endpoint is `0x39 + 0x20 = 0x59 = 89` bytes. This gives a minimum accessed carrier extent for the inspected copy paths. Its complete type, producer allocation and upstream validation remain unknown.

| State-object offset / interval | Width | Established effect |
| --- | --- | --- |
| `+0x00` | u32 | Source writes raw scalar `0x80` |
| `[+0x04,+0xac)` | 168 bytes | Initially zeroed by original helper |
| `[+0x04,+0x14)` | 16 bytes | Optional modeled copy of opaque span A |
| `+0x24` | u32 | Raw control word |
| `+0x28` | u32 | Companion scalar 0 or 32 on inspected paths |
| `[+0x2c,+0x4c)` | 32 bytes | Optional modeled copy of opaque span B |
| `[+0xac,+0xb0)` | 4 bytes | Outside the clear interval; preserved in current cases |
| `[+0xb0,+0xc0)` | 16 bytes | Per-sample opaque span C; outside the initial clear interval |
| `+0xc0` | u32 | Earlier source operand, zero in these fixtures; full role unresolved |
| `+0xc4` | u32 | Initially reset to zero; later four-byte sample-size read destination |

The observed `+0xc4` access requires at least `0xc4 + 4 = 0xc8 = 200` bytes for these paths. The earlier guard adds `0x140 = 320` to an object operand, but neither the guard nor these accesses establish its allocation size. The raw scalar `0x80` is not established as a byte extent, bit count or complete structure size.

## Exhaustive input-byte partition in declared state

The 1024 count-zero cases cover all 256 values of byte `+0x01`, both values 0/1 for byte `+0x38`, and null/non-null allocation results. Twenty additional cases cover count one for representative branches. Original byte loads, comparisons and store sites corroborate the partition independently of the fixtures.

| Carrier byte `+0x01` | Byte `+0x38` | State u32 `+0x24` | State u32 `+0x28` | Opaque setup copies |
| --- | --- | --- | --- | --- |
| 1 | Not consulted here | 2201 (`0x899`) | 0 | None |
| 2 | Not consulted here | 2204 (`0x89c`) | 0 | None |
| 3 | Not consulted here | 3100 (`0xc1c`) | 32 | A:16 bytes; B:32 bytes |
| All other u8 values | 0 | 0 | 0 | A:16 bytes |
| All other u8 values | Nonzero | 3000 (`0xbb8`) | 32 | A:16 bytes; B:32 bytes |

The default comparison is with zero; the runtime fixtures exercise 0 and 1, while the source u8 comparison identifies the remaining nonzero partition. These are local state-construction choices, not proof that every byte value is accepted by upstream/native interfaces. No algorithm, key class or cryptographic material meaning is assigned to the control codes or opaque spans. SS4/SS5 apply.

The fresh verifier reconstructs each final state object by merging original source writes and modeled copy events in visit order. It checks 1044 resulting objects, 175392 original clear bytes, 1556 modeled copy calls and 33184 modeled copy bytes. Original control-byte reads remain distinct from the model's synthetic payload reads.

## Fill helper: exact raw-register behavior

Function `0xfffffe000a687d64..0xfffffe000a687ecc` has 90 original instructions. It uses a byte prefix for alignment, unrolled qword stores, then a byte tail. For destination D, length L and incoming X1 value V:

```
A = (-D) & 7
P = min(L, A)
R = L - P
Q = floor(R / 8)
T = R mod 8
W = (low32(V) * 0x0101010101010101) mod 2^64

written bytes = low8(V) repeated P times
             || little_endian64(W) repeated Q times
             || low8(V) repeated T times
incidental X0 at RET = D + L - (T != 0)
```

P, R, T and L denote byte counts; Q counts 8-byte stores. The address expression uses u64 modular arithmetic. Valid native buffers, nonwrapping extents and a C return type are separate prerequisites, not consequences of these equations.

For canonical byte values `0..255`, W repeats that byte eight times. For the declared eight-byte-aligned object fixtures, the setup call has V zero, D at object `+0x04`, L 168 bytes, P 4, Q 20 and T 4. Native object alignment remains unknown; the general equations retain D explicitly. The write count is `4 + 20*8 + 4 = 168` bytes, through object `+0xab` inclusive. Incidental X0 is object `+0xab`. The caller does not use that register as a returned destination.

The helper does not mask W1 to eight bits before its qword multiplication. Raw-register width-stress cases can therefore differ from a uniform low-byte fill. For example W1 `0x101` gives qword `0x0202020202020201`; byte-prefix/tail stores still use byte `0x01`. This is not a demonstrated native calling-convention violation: the helper's required input domain is unknown and its inspected caller passes zero.

All 6104 fresh cases check exact written-byte coverage, no duplicate/out-of-extent stores, unchanged 16-byte guards and the mathematical result. They cover all eight destination alignments, lengths through 192, every canonical byte at selected lengths, wider register values and selected lengths through 8192. There are 5784 canonical-byte cases, 320 raw-width cases and 132 observed nonuniform width-stress outputs. Six local proofs cover alignment width, canonical repeated bytes, prefix bounds, length partition, unrolled-loop word count and ignored upper X1 bits. They are local identities, not a universal proof of the complete helper or native memory behavior. SS1/SS3 apply.

The supplied C at line 233287 prints a `_BYTE *` return type and unsigned u32 fill operand. Original RET-register observations support the advanced-pointer calculation; they do not establish a unique C prototype. The behavior cannot be assigned the standard `memset` return contract merely from its fill effect.

## Exact copy and allocation interfaces

| Site / binding | Target / effect |
| --- | --- |
| Clear call `0xfffffe000a6252dc` | Original helper `0xfffffe000a687d64`, `(object+4, 0, 168)` |
| Copy thunk `0xfffffe000a508cf4` | `BTI C; B 0xfffffe000a69f334` |
| Import stub `0xfffffe000a69f334` | Authenticated branch through slot `0xfffffe000847c4c8` |
| Original slot target | `0xfffffe000c647f10`; exact aliases `_memcpy` and `_memmove` |
| Setup copy sites | `a6253e0`, `a625448`, `a6254b8`, `a625574`, all with address prefix `0xfffffe000` |
| Per-sample copy site | `0xfffffe000a625a4c`: `(object+0xb0, carrier+0x12, 16)` |
| Workspace allocation | `0xfffffe000a6255e4` -> `0xfffffe000c4ba60c`, exact `_IOMallocData` / `_IOMallocData_external`, X0 = 8192 |
| Workspace release | `0xfffffe000a6256f4` -> `0xfffffe000c4ba84c`, exact `_IOFreeData`, X0 = workspace, X1 = 8192 |
| Sample-size read boundary | `0xfffffe000a625c6c` -> `0xfffffe000a509a60`, first observed arguments `(0, object+0xc4, 4)` |

Original chained-pointer membership and all ten selected bank identities are rechecked. The two copy aliases share one exact kernel address; unique source-level import naming is unresolved. Both interfaces agree for the declared nonoverlapping spans. Their behavior is modeled rather than executed, and native aliasing/pointer validity remain unknown.

The sample-size caller forms a byte offset by `UBFIZ X0, X8, #2, #0x20`; this preserves the full34 result of a u32 element index times four. In the ten nonempty cases the index is zero. The destination is a four-byte state field, not the 8192-byte workspace. The wrapper's existing full64 IOByteCount return contract remains distinct from the caller's later `CMP W0, W8` at `0xfffffe000a625c8c`. No read result or data is supplied in this increment.

## Deeper allocation/free argument mapping

The matching kernel wrappers share literal context operand `0xfffffe0007f8bfb0`:

| Wrapper | Deeper callee | Registers at original transfer |
| --- | --- | --- |
| `IOMallocData` | `0xfffffe000bcfe5b8` | X0=context; X1=request64; W2=`0x31000`; X3=0 |
| `IOFreeData` | `0xfffffe000bcfec48` | X0=context; X1=pointer64; X2=extent64 |

The exact names and types of both deeper callees and the context operand are **unknown**: exact-symbol queries return no symbols. No neighboring symbol is substituted. The public wrapper identities establish an IOKit data-allocation touchpoint without naming the deeper heap domain.

On a nonnull allocation result, original code atomically adds the requested size at `0xfffffe000cb5b620`. The nonnull free path atomically subtracts the supplied extent at that same cell. Allocation-null and free-null branches skip those operations. Additional accounting is conditional on size and a runtime flag; it is not executed here. Native heap selection, allocation contents, synchronization and real counters remain unobserved.

Pinned SDK `IOLib.h` describes `IOMallocData` as allocating data memory and distinguishes it from its zeroing variant. Its declarations use `vm_size_t` and give `IOFreeData` a void result. The compile-only probe confirms an eight-byte SDK extent and emits branches to the named public APIs. These are corroborating SDK contracts, not proof of exact private ABI/type equality with the collection's build. Original X-register moves independently establish the recovered widths. SS6 applies.

The workspace request is 8192 bytes. It is distinct from the previously recovered 81920-byte IOBufferMemoryDescriptor request; equal facility names do not identify the same allocation or lifetime.

## Conditional cleanup and lifetime limits

| Declared path | Original ordering after setup | Stored status word |
| --- | --- | --- |
| Workspace allocation null, 522 cases | Samples release; sample-size complete; sample-size release | `0xce515bb2` |
| Nonnull workspace, empty loop, 512 cases | Workspace free(8192); same descriptor suffix | `0x31ae0066` |
| Nonnull workspace, one-element prefix, 10 cases | Opaque C copy; stop before four-byte sample-size read | No final status claimed |

The status words retain the previous report's XOR carrier convention; this increment does not interpret incidental X0 after void free/release as a status. In the 1034 complete modeled returns, the path contains samples preparation and samples release without an explicit call to the samples-complete helper. Sample-size completion is explicit before its release. Native release/destructor behavior, valid preparation state and implicit completion remain unresolved; this observation does not establish a native leak or incorrect retirement. SS7 applies.

Nonempty source data flow continues through the descriptor read, returned-count test and loaded u32 sample-size checks. Those operations are the next unresolved boundary. Actual sample bytes, workspace initialization, downstream AES calls and complete processing remain unproved.

## Reproduction and assumptions

The fresh verifier re-reads functions, exact symbols, import slots, bank bytes, compiler/SDK output and proof files. It then replays the original fill/state cases and reconstructs state from source writes plus explicitly modeled copies. Cost is O(Cs*(B+Vs)+Cf*(Vf+L)+I+E) time and O(B+retained cases/events) space, plus solver/compiler-dependent work. Cs/Cf count state/fill cases, B mapped bytes, Vs/Vf bounded visits, L fill bytes, I inspected source and E events. Source caps are 20000 instructions per state/fill case.

```
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_sample_state.py
```

This was the pre-publication command. Published artifacts remain frozen; reproduction requires a separate copy and distinct outputs.

| ID | Assumption / boundary | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| SS1 | Pinned original KC/normalized image and exact compiler spans identify this build | All source bindings and local helper recovery | Rehash originals; compare source bytes, symbols and chain membership |
| SS2 | Selector/state, objects, carrier, task and helper results are declared fixtures | 1044 conditional source paths, not native reachability | Retain input bytes, source visits, definedness and original/model event order; establish actual predecessors separately |
| SS3 | Fill-model comparisons concern mapped private buffers and raw registers | Exact finite helper effects and local identities | All alignments, byte values, length residues, guards and wider-W1 stress; native domain/prototype remains unknown |
| SS4 | Carrier/object types and upstream validation are unknown | Partial offset/extent contracts, not a public wire schema | Trace both producers and aliases; preserve packed byte offsets and distinct initialization epochs |
| SS5 | Copies use synthetic opaque spans and assume declared nonoverlap | State reconstruction only | Verify exact source/destination extents and alias pair; actual contents and native aliases remain unknown |
| SS6 | SDK supplies public contract context, not a matched private implementation version | Type/zeroing/void API labels | Pin header and compile output; retain original register moves and unknown deeper names |
| SS7 | Descriptor/heap actions and their results are modeled; native destructor/reference effects are unknown | Conditional cleanup order and stored words | Null/non-null workspace, void-register fixtures and explicit source calls; inspect destructor/ownership paths separately |
| SS8 | Authentication is abstracted and execution stops before unmodeled descriptor reads | Source-derived control/data prefixes only | Retain original modifiers and pointer metadata; recover actual runtime/PAC and native I/O independently |

| Impact | Further investigation | Question resolved |
| --- | --- | --- |
| High | Follow the four-byte size read through count/result gates and subsequent descriptor accesses | Actual per-sample data flow and workspace use |
| High | Trace state fields into the provider ABI before assigning key/IV/control meanings | Business semantics of the opaque carrier and raw codes |
| High | Establish actual descriptor destructor/implicit-completion behavior and caller serialization | Native retirement and interactions between global descriptors |
| High | Prove input/frame predecessors and task ownership | Native entry reachability and address-space provenance |
| Medium | Recover deeper allocation callee/context types from additional primary metadata | Precise heap-domain and allocation-flag interpretation |
| Medium | Audit the fill helper's other callers and required W1 domain | Correct semantic naming and return-register use |
| Medium | Preserve byte offsets and initialization epochs in any recovered structure | Avoid treating raw `0x80` as object size or clearing opaque C prematurely |

QG1: factual analysis requires no normative conclusion. QG2: SS1-SS8 specify assumptions and falsification probes. QG3: state/carrier, pure helper, copy/heap ABI, conditional lifetime and next data-read boundary are covered for this increment; the full goal remains active. QG4: widths, byte intervals, arithmetic, source coverage and complexity are reproducible. QG5: raw scalars/extents, native/model operations, advanced X0/C return type, alias names and explicit/implicit completion are distinguished. QG6: original bytes/symbols/chains, ten exhaustive banks, six proofs, 7148 fresh cases and SDK evidence support the stated bounds. QG7: impact-labeled continuation is complete.

[Delivery quality gates](triage_evidence/sample_state_quality_gates.json) record final source, prior-artifact and report-link verification.
