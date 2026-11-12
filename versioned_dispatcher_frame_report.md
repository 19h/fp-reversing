# Selector-21 dispatcher frame provenance and stream allocation

The complete compiler-bounded dispatcher contains three direct stores to body SP+`0x130`, all beyond the previous bounded capture. Two copy SP+`0x134`; one saves W24 before reusing that register. None occurs in the 12 retained mode-2 paths before their unresolved read. An independent symbolic source slice carries an arbitrary u32 in W24 and resolves the next pending call to `_IOMallocTypeImpl`, with type-view name `site.FPByteArrayStreamInternal` and declared allocation size 32 B. Its branches, read addresses and call argument do not depend on that word. The private guest receipts remain stopped before the load. [DF1-DF6]

```text
retained helper return -> STOP before LDR W24,[SP+0x130]
                              |
                    independent symbolic source slice
                    W24 = arbitrary u32; frame unchanged
                              |
                   pointer/count guard -> two bank lookups
                              |
                   pending typed allocation: 32 B stream object

other source blocks: SP+0x134 -> SP+0x130
                     W24    -> SP+0x130 -> W24
```

Subsequent continuation: the [stream-initialization report](versioned_stream_initialization_report.md) follows declared allocation returns through object construction, backward scanning and pending cleanup. It preserves this report's unresolved W24 origin and establishes the selected path's next unspecified frame read at `0xfffffe000a5a731c`. No original guest receipt is continued.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| DF-A1 | Original KC, normalized kext and pinned preparation receipt identify these exact builds. All address joins depend on it. | Hash pins; original/normalized instruction equality; original chained-pointer membership and decoding. A changed build invalidates the correspondence. |
| DF-A2 | Compiler function-start metadata brackets one function; body SP G and FP=G+`0x250` describe its non-epilogue blocks. Census ownership depends on it. | Decode every instruction through the next compiler start; enumerate SP adjustments; exclude prologue and the restoring epilogue from body-offset matching. Computed aliases remain outside the census. |
| DF-A3 | The pinned private prefixes, including successful workspace/auxiliary allocations, supply the boundary registers and defined byte epochs. Symbolic continuation depends on it. | Reconstruct all 103,764 retained source visits and memory events from initial cells and ordered writes. This is receipt validation, not fresh guest execution or native admission. |
| DF-A4 | The unresolved frame load is represented by an unconstrained u32 in W24, with A64 zero extension. No frame byte is initialized. | Confirm zero known bytes before the load and W24 still symbolic at the pending call; reject every later unspecified private read or symbolic control/address/argument. |
| DF-A5 | Fixed byte cells and the retained guest spans retain their stated ownership and nonaliasing. Slice memory joins depend on it. | Check private known-byte membership, original image bytes and original chained-pointer fixups. Native kernel buffer aliasing remains unknown. |
| DF-A6 | The recovered type-view fields use the typed allocator record convention established by the core-entry analysis. The 32 B allocation interpretation depends on it. | Resolve both original pointer fields, the exact name, flags and size; resolve the call target to the KC allocator symbol. Runtime allocation and object field layout remain unknown. |
| DF-A7 | Static authenticated target/diversity agreement is conditional on valid native authentication. Control transfers depend on it. | Check all 36 transfer records against original chains; do not credit native PAC, allocator execution or a live transaction. |

## Complete function boundary and slot producers

The KC compiler function-start table brackets `0xfffffe000a5a5470..0xfffffe000a5a9324` (exclusive end): 4,013 instruction words, 16,052 B. Every captured instruction agrees with the normalized kext. The previous census covered only `0xfffffe000a5a5494..0xfffffe000a5a729c`, 1,922 words. Its zero-store result was scoped to that prefix; it was not a whole-function absence claim. A direct branch at `0xfffffe000a5a7080` targets `0xfffffe000a5a900c`, explicitly joining the later blocks to the earlier body. [DF1-DF2]

After the prologue, G=entry SP-`0x260` and FP=G+`0x250`. The only explicit ADD/SUB changes to SP are the body allocation at `0xfffffe000a5a5490` and restoration at `0xfffffe000a5a729c`. The remaining entry/exit STP/LDP writeback is excluded from body-offset matching. [DF2]

| Direct SP+`0x130` store | Source value | Established local role |
| --- | --- | --- |
| `0xfffffe000a5a76f0` | W10 loaded from SP+`0x134` at `0xfffffe000a5a76ec` | Copies an existing carried word. |
| `0xfffffe000a5a8150` | W24 | Saves W24 before `AND W24,W8,W9`; `0xfffffe000a5a8254` reloads the saved word. |
| `0xfffffe000a5a8d58` | W10 loaded from SP+`0x134` at `0xfffffe000a5a8d54` | Another copy of an existing carried word. |

Four source-lift obligations prove these save/restore/relay equations for arbitrary u32 values. The census also retains all 19 direct accesses overlapping `[G+0x130,G+0x138)`, including seven stores to the neighboring slot. Those neighboring stores have multiple sources; the two slots are not assigned one universal semantic field. No immediate ADD/SUB SP/FP pointer producer into this 8 B region is found. Computed aliases, predecessor reachability and incoming native frame contents remain unknown. [DF2-DF3]

The three SP+`0x130` stores are absent from each retained prefix. Thus they do not establish a producer for the read at `0xfffffe000a5a6e5c`. The initial unknown value is neither replaced nor attributed to a native defect. [DF4]

## Control and allocation contract beyond the unresolved read

Two further source-lift obligations recover the preceding helper-status selection and following pointer/count guard, with arithmetic modulo 2^32: [DF3]

```text
status == 0x31ae0066 ? table index 0x5a2 : 0x13e
  success index 0x5a2 -> 0xfffffe000a5a6e68

inputB != 0 AND count != 0 ? table index 0xbb8 : 0xbb1
  index 0xbb8 -> 0xfffffe000a5a6eac
  index 0xbb1 -> 0xfffffe000a5a7290
```

The count comparison is unsigned equality to zero, not an upper-bound check. Retained input-B pointers are nonzero and counts are 16 B, so all twelve slices select `0xbb8`. The preceding UserClient bound remains a separate contract. [DF3-DF4]

Each slice starts after the unresolved load, seeds W24 with a symbolic u32, preserves all four frame bytes as unspecified, and lifts 69 original instructions. W24 is not read or modified by those 69 instructions. The slice performs 15 memory reads / 80 B, two authenticated transfers, and stops before `0xfffffe000a5a6f74`. No guest continuation, allocator model, memory write or native call is performed. The twelve independence checks are structural nondependence checks over an unused carried symbol, rather than twelve additional general-purpose arithmetic identities. [DF4]

| Original call/interface field | Recovered value |
| --- | --- |
| Call PC | `0xfffffe000a5a6f74`, `BLRAA X10,X17` |
| Function-pointer slot | `0xfffffe000847a7b8` |
| Target / KC symbol | `0xfffffe000c4ba154` / `_IOMallocTypeImpl` |
| Authentication modifier | `0xd0c8` |
| X0 / type-view address | `0xfffffe000847b320` |
| Type-view name | `site.FPByteArrayStreamInternal` |
| Type-view flags / size | `0x64` / 32 B |
| Second static pointer field's bytes | ASCII `1222`; further meaning unknown |
| Runtime return, object layout and lifetime | unknown |

The 32 B object is separate from the previously established 16,384 B workspace and 4,096 B auxiliary allocation, even though this call uses the same allocator function and authenticated pointer slot as the auxiliary allocation. The type-view name supports the byte-stream allocation role; it does not establish the object's field layout or complete protocol semantics. [DF5]

Two bank identities exhaust all 256 input bytes each. If L and R denote the recorded original 256 B tables, then:

| Selection | Universal byte identity | Index / selected result |
| --- | --- | --- |
| Allocator | `x XOR R[L[x] XOR 0x73] = 0x47` | TABLE[`0xecc+0x47`] -> `_IOMallocTypeImpl` |
| Type view | `x XOR R[L[x] XOR 0x37] = 0x3a` | POOL[`0x199+0x3a`] minus 12 B -> `0xfffffe000847b320` |

The source uses current global words to form the two input bytes. The exhaustive identities remove dependence of these selected results on those bytes, conditional on the same table bases. The twelve slices retain two guest placements/global fixtures, baseline, block-bit and generated-bit profiles, and the two preceding daemon source fixtures. Native state and build pairing remain unknown. [DF4-DF5]

No new Mach port, IPC message, right transfer or emission site is established. The existing daemon `_IOConnectCallStructMethod` call at `0x100478a04` remains the cross-level API boundary; this increment describes a later internal kernel allocation under the already declared argument correspondence.

## Provenance, reproduction and bounded continuation

| ID | Primary evidence |
| --- | --- |
| DF1 | KC SHA256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized kext `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Compiler metadata and instruction bytes are read afresh. |
| DF2 | [Extractor and symbolic slice](triage_evidence/recover_versioned_dispatcher_frame.py): complete function bytes, frame census, direct cross-boundary branch and original-chain pointer records. |
| DF3 | [Compressed receipt](triage_evidence/versioned_dispatcher_frame_checks.json.zst): six source equations / 28 lifted instructions; all negated claims UNSAT. |
| DF4 | Preparation receipt SHA256 `b5a8adb34c380be6daf899d7b481a7a55e7e814b353ee24a39c076f88d781941`; twelve retained mode-2 cases, 103,764 old source visits, 95,088 read bytes and 31,104 write bytes independently reconstructed. New symbolic slices total 828 instructions / 960 read bytes; no new guest execution is credited. |
| DF5 | Two exhaustive bank rules / 512 byte inputs, 36 original authenticated transfer checks and two original type-view pointer fields. The exact allocator symbol and type name are source evidence. |
| DF6 | [Publication verifier](triage_evidence/verify_versioned_dispatcher_frame_publication.py): fresh extractor equality, frozen SMT checks, independent raw-word store scan, unknown-dependency rejection controls, archive/hash/path hygiene and exact publication delta. IDA was unnecessary because original source bytes and compiler metadata suffice. |

Reproduce by running the extractor and publication verifier with the pinned project's Python dependencies. The extractor writes the logical receipt; publication compresses it with zstd level 22 and verifies the decompressed bytes before removing the plaintext. Cost is O(receipt bytes+I+C*V+256R) time/space, with solver queries capped at 30 s and each symbolic slice capped at 100 instructions. Six source equations and twelve carried-symbol independence checks remain distinct in the receipt.

| Impact | Further bounded work | Required evidence |
| --- | --- | --- |
| High | Follow stream initialization, allocation failure and cleanup. | Original post-call paths and type/lifetime fields; declare any allocation model separately. |
| High | Establish the initial carried-word producer or valid-path exclusion. | Reachable predecessors, neighboring-slot definitions and computed aliases; retain the original unknown origin. |
| High | Establish native daemon/UserClient ownership and pairing. | Matching build/task/connection/right epoch and a recorded transaction. |
| Medium | Recover compact stream and block-format semantics. | Source field transitions and independent valid-format/reference evidence; names and finite outputs alone are insufficient. |

- **QG1**: Pass. Factual source/interface analysis requires no normative content.
- **QG2**: Pass. DF-A1..DF-A7 identify premises, dependencies and falsification probes.
- **QG3**: Pass for this increment. Full function scope, slot producers, control equations, environmental selection and the next allocation contract are covered. The full goal remains active.
- **QG4**: Pass. Extents use B, A64 words use 4 B, scalar equations specify modulo 2^32, and old receipt visits are separate from new symbolic slices.
- **QG5**: Pass. Possible stores, executed prefixes, symbolic carry, native initialization and allocator completion are distinct; no blanket absence claim remains implied.
- **QG6**: Pass. Original bytes, chained pointers, compiler metadata, frozen receipts and symbolic premises are traceable to the listed artifacts.
- **QG7**: Pass. Additional control/data/environment and ownership work is bounded and impact-ranked above.
