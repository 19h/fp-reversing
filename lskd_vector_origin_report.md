# LSKD cached vector origin, typed elements and allocation-failure release

The start continuation writes the typed allocation result to `0xfffffe000ccc78d0` at `0xfffffe000a5116d0`. Its original descriptor names `site.KDDecryptParamsArray_t` and declares 8,192 B. This supplies a source producer for the vector base used by the [lookup readers](lskd_objects_report.md): `1024 * 8 B = 8192 B`. The successful arm next allocates a 512 B `site.KDDecryptParams` element, stores its pointer in slot zero, initializes selected fields and clears the corresponding tag. Actual native pointers, a completed initialization loop and a matched reader epoch remain **unknown**. [VO1-VO6]

The vector-null arm saves raw status `0x5e5571ad`, prepares release selector `0x1d3` with a null explicit pointer, and calls the previously recovered cached-RW-lock release adapter. After that adapter returns, it reloads the saved status and reaches the common result store. This extends the [start/lock report](lskd_start_lock_flow_report.md) across acquisition, typed allocation, publication and the conditional failure release. It establishes no new daemon reply or Mach port. [VO3-VO8]

[Original source and checks](triage_evidence/lskd_vector_origin_checks.json.zst), the [extractor](triage_evidence/recover_lskd_vector_origin.py) and the [publication audit](triage_evidence/verify_lskd_vector_origin_publication.py) retain the evidence. Ten kext spans contain 369 instructions, occupying 1,476 B. Five exhaustive banks cover 1,280 inputs, seven authenticated continuation slots are decoded, and two original typed descriptors and two native allocator functions are retained. Thirteen prior start frames are reconstructed at twenty fields each, checking seventeen distinct original producer PCs. Sixteen UNSAT queries cover 143 source-lifted instruction instances. No new target execution, allocation, entropy generation, synchronization or IDA access occurred.

```text
start: entropy -> seed publication -> RW construction -> acquire adapter
  returning acquisition
    -> IOMallocTypeImpl(array view, declared 8192 B)
    -> CCC78D0 = returned pointer             [publication before null gate]
         null -> save raw 5E5571AD
                 -> release record: phase 1D3, explicit pointer null
                 -> cached RW release adapter
                 -> reload saved raw status -> outer result +38
         nonnull -> index = 0
                    -> IOMallocTypeImpl(element view, declared 512 B)
                    -> vector[index] = returned pointer
                    -> 47 field writes covering 164 B
                    -> tag[index] = u32 0
                    -> reload vector[index] and test it
                         nonnull -> A51B9D8 [next source frontier]
                         null    -> A547FC8 [untraced continuation]
```

Addresses in the diagram abbreviate prefix `0xfffffe000`. All call/return and memory effects are conditional source order. The late slot test is not an earlier allocator-result guard: the source writes element fields before that test. The allocator's admissible native outcomes remain unknown; no failing element allocation or native fault was executed.

## Evidence identity and reference coverage

The pinned original kernel collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized kext SHA-256 is `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Every captured kext instruction is compared between these two representations. Original format-8 chain membership is checked for each selected pointer. Authentication diversity is static metadata; hardware authentication remains unobserved. [VO1]

The supplied C at lines 52267-52421 retains the element-pointer store, field writes and tag clear. Lines 43372-43387 retain the vector-failure status store; lines 95130-95212 retain release preparation. The C function at `0xfffffe000a511608` does not expose the following allocation/publication block as recovered live C control flow. Original instructions at `0xfffffe000a51162c..0xfffffe000a511708` supply that missing evidence. A nearest function name or empty call-list edge cannot establish the block's register contract. The three original supplied inputs remain unchanged; no database lookup was needed.

## Frame and register handoff

The retained frames are the same thirteen finite cases that stopped before `read_random` in the preceding report. They do not execute the later continuation. The new extractor reconstructs byte epochs from their ordered writes and checks each last producer against the original bytes. The source composition additionally assumes that returning callees preserve the caller frame and callee-saved registers, without undeclared aliases. [VO2-VO4]

| Retained SP field | Value or role at the retained boundary | Later source use |
| --- | --- | --- |
| `+8` | Tag root `0xfffffe000ccc7b08` | Carried through acquisition preparation; element tag clear |
| `+0x88` | Vector cell `0xfffffe000ccc78d0` | Loaded into X26 after acquisition |
| `+0xa0`, `+0xa8` | `0xfffffe00079172c0`, `0xfffffe0007919cb0` | Array allocator and element-view byte banks |
| `+0xb0`, `+0xb8` | `0xfffffe000791d3b0`, `0xfffffe0007920e10` | Array-view bank |
| `+0x100` | Dispatch root `0xfffffe000846c420` | Carried into X28 by the construction caller |
| `+0x108`, `+0x110` | `0xfffffe00079173c0`, `0xfffffe0007920d10` | Right/left banks for the element allocator |
| `+0x120` | Workspace W`+0x80` | Scratch base; vector-failure status at W`+0x180` |
| `+0x128` | Workspace W`+0xa8` | Reused acquisition/release record |
| `+0x160` | Actual auxiliary base A | Restored into X25 after acquisition |
| `+0x168`, `+0x170` | `0xfffffe0007920c10`, `0xfffffe00079170c0` | Release-adapter bank |
| `+0x178`, `+0x180` | `0xfffffe000ccc2d90`, `0xfffffe000ccc2c60` | Opaque control-word locations |
| `+0x198` | Workspace W`+0x40` | Common result receiver |
| `+0x1a0` | u32 `0x3be` | Start-state constant for allocation and failure dispatch |

The success fragment at `0xfffffe000a54a228` establishes W23=`0xea5ebdeb`; `0xfffffe000a54a238` loads X24 from SP`+0x110`. It carries the tag root and C-bank pair through explicit stores at `0xfffffe000a531ca4..0xfffffe000a531cac`. The acquisition preparer sets W21=`0xe3`; after its returning call, `0xfffffe000a531d68` loads X26 from SP`+0x88`. The previously checked continuation slot `0x5b` enters `0xfffffe000a51162c`. The saved SP`+0x18` word and the restored auxiliary base at SP`+0x160` are distinct fields; this report does not identify them by proximity.

## Typed allocation contracts and vector publication

Each bank exhausts all 256 low-byte inputs. Consequently, its selected slot does not require a concrete runtime value for the opaque control words. The original pointer, its metadata and any subsequent address bias are checked separately. [VO1,VO3]

| Source use | Original slot | Decoded target and bias | Effective target |
| --- | --- | --- | --- |
| Array/element allocator | `0xfffffe0008471368` | Code, diversity `0xb389` | `0xfffffe000c4ba154`, exact `_IOMallocTypeImpl` |
| Array view | `0xfffffe00084717a8` | `0xfffffe000847af2c`, subtract 12 B | `0xfffffe000847af20` |
| Element view | `0xfffffe0008471a80` | `0xfffffe000847b068`, subtract 8 B | `0xfffffe000847b060` |
| Failure release adapter | `0xfffffe0008471498` | Code, diversity `0x84cc` | `0xfffffe000a551f38` |

| View address | Original site-name bytes | Flags at `+0x28` | Size at `+0x2c` |
| --- | --- | --- | --- |
| `0xfffffe000847af20` | `site.KDDecryptParamsArray_t` | `0xe4` | 8192 B |
| `0xfffffe000847b060` | `site.KDDecryptParams` | `0x64` | 512 B |

The site names are allocator metadata labels. They do not establish a complete C/C++ declaration, field names or a vtable. Both descriptors have sixteen zero file bytes at their leading runtime-link area; their initialized native links are unknown. Original pointer fields at offsets 16 and 32 are decoded independently. The original `_IOMallocTypeImpl` reads view flags and tail-calls exact `_kalloc_type_impl` at `0xfffffe000bcfeb8c`; both complete source functions are retained. For either stated flag word, its shown wrapper selects W1=`0x8004`. This does not establish heap contents, native allocation capacity, null-return admissibility or a successful call.

At array call `0xfffffe000a5116c8`, X0 is the array-view address. The returning X0 is stored directly into the vector cell at `0xfffffe000a5116d0`, including zero if the allocator returns zero. The source initializes X21=0, then tests the returned pointer. Under saved phase `0x3be`, W19=`0x7fe` and W20=`0x4f7`; the selector is

```text
index = ((returned_pointer == 0) * (7FE XOR 59C)) XOR 4F7
      = 695 when null; 4F7 when nonnull
```

Original index `0x695` targets `0xfffffe000a529758`; index `0x4f7` targets `0xfffffe000a5341f0`, both diversity `0xb064`. The 8,192 B declaration agrees with the readers' indexed extent. It does not prove that all 1,024 entries are populated, that the entire array is cleared, or that a native reader sees this allocation epoch. The first source element index is zero. Later iteration and object transformation remain open.

## First element and paired tag initialization

The nonnull-vector continuation selects `_IOMallocTypeImpl` again at `0xfffffe000a5342a0`, now with the 512 B element descriptor. At `0xfffffe000a5342b0` it stores the returned pointer to `vector+8*index`. It then writes the following element-relative fields. All offsets and extents below are bytes. [VO3-VO6]

| Element offsets | Width at each offset | Stored value |
| --- | --- | --- |
| `0xe0`, `0xf8`, `0x130`, `0x144`, `0x170`, `0x1e0` | u32 | `0x13f6f63f` |
| `0xfc`, `0xfe`, ..., `0x12a` | 24 u16 fields | Zero |
| `0x148`, `0x1d8`, `0x1dc`, `0x1f8` | u32 | Zero |
| `0x14c`, `0x174`, `0x180` | u8 | Zero |
| `0x175` | u8 | One |
| `0xf0`, `0x168`, `0x1d0` | u64 | Zero |
| `0xe8`, `0x158`, `0x1f0` | u64 | `0x908b69373110a675` |
| `0x160` | u64 | `0x40791ac78bd5c571` |
| `0x178` | u64 | `0x54ac365113f503fb` |
| `0x1e8` | u64 | `0x35371c5d81e56cd2` |

These are 47 typed memory writes, with paired-store instructions contributing two writes each. Their union covers 164 B; the largest exclusive end is `0x1fc` = 508 B, within the 512 B declaration. The slice leaves 348 declared bytes unwritten. The extractor retains every source PC, width, offset and value. It does not assign semantic field names or infer preexisting contents for unwritten bytes.

The tag store at `0xfffffe000a5343b4` then writes zero to `0xfffffe000ccc7b08+4*index`. This supplies one concrete source tag-table writer and connects vector-slot preparation to the readers' zero-tag sentinel. For any unsigned index below 1024, the local formulas satisfy `8*index+8 <= 8192 B` and `4*index+4 <= 4096 B`; these are offset bounds, not arbitrary base-pointer validity or allocation-success proofs. Only index zero is established on this incoming continuation.

The source reloads the vector cell and slot before its null test at `0xfffffe000a5343c0`. Under a stable vector/slot epoch the loaded slot equals the pointer just stored. Without that premise, the test concerns a fresh load, not necessarily the allocator result. Its nonnull/null indices are `0x7fe`/`0x82c`, targeting `0xfffffe000a51b9d8`/`0xfffffe000a547fc8`, diversity `0xf019`. Their subsequent bodies are outside this increment. The earlier field writes require an accessible returned element under the declared source-memory premise.

## Vector-allocation failure and release ABI

On the vector-null arm, the source already stored null into the vector cell. At `0xfffffe000a529760`, it saves W9=`0x5e5571ad` into scratch `+0x100`, namely W`+0x180`. It selects index `0x579` and target `0xfffffe000a56e020`, diversity `0x83c6`, while retaining W8=`0x14` as the subsequent return-continuation index. [VO3,VO7-VO8]

For release record R=W`+0xa8`, the original key basis reduces to `low32(R) XOR 0xdfb9786f`. The source writes

```text
key32 = u32((low32(R) XOR DFB9786F) * 1E2776FD)
record_u32[0] = u32(key32 + (3BE - 1EB)) = u32(key32 + 1D3)
record_u64[+8] = 0
```

The adapter decodes selector `0x1d3` from that first word. At `0xfffffe000a56e0c4`, the exhaustive E-bank selects `0xfffffe000a551f38`, the [existing release adapter](lskd_continuations_report.md). With a null explicit pointer, that adapter freshly reads RW cell `0xfffffe000ccc78a8` and selects `IORWLockUnlock` if nonnull. Matching it to the prior acquisition requires the same valid lock epoch; the source record alone does not establish that epoch or actual ownership.

After the adapter returns, saved continuation `0x14` targets `0xfffffe000a56bc1c`, diversity `0xc38e`. This block reloads the scratch status, compares it to raw success `0x5e561849`, and for `0x5e5571ad` selects index `0x3be`. That original slot targets the common return `0xfffffe000a52e4b0`, diversity `0x62dc`; `0xfffffe000a52e4b8` writes the saved raw status to receiver `+0x38`. An intermediate register constant written immediately after release is overwritten by the scratch reload and must not be substituted for the returned status.

The captured caller suffix contains no RW-free call or reset of the prior seed pointer/flag. It establishes a release-adapter handoff and raw-result return, not reclamation or a global readiness transition. The vector cell is null on this source arm. Actual allocator outcomes, release execution, other writers and outer daemon error translation remain unknown.

## Assumption register

| ID | Assumption and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| VO1 | Pinned original KC and normalized kext identify this build. All addresses, site labels and slots depend on that identity. | Rehash both; compare instructions and original format-8 pointer chains, site strings and metadata. |
| VO2 | Thirteen retained prefixes describe their declared finite start fixtures. Frame-root attribution depends on these byte epochs. | Reconstruct ordered writes and last producers; establish actual native entry/backing objects separately. |
| VO3 | Calls return normally and preserve callee-saved registers and the caller frame without undeclared aliases. Continuation composition depends on this. | Audit each actual call/return and reaching frame store; no new call executes here. |
| VO4 | Original byte banks remain unchanged and opaque control-word loads are accessible. Constant target selection depends on this. | Exhaust all 256 inputs per rule and compare original/normalized bank bytes and destination slots. |
| VO5 | A returning nonnull element pointer designates accessible storage for the shown field writes. Initializer effects depend on this premise. | Establish the actual allocator contract, result, backing capacity and admissible outcomes; do not use the later slot test as an earlier guard. |
| VO6 | A stable vector/slot/tag epoch joins this producer to the reader's base and index. Object-identity conclusions depend on this. | Identify all intervening writers, reader epochs and transformations; this increment establishes no complete population loop or native match. |
| VO7 | Release phase `0x1d3` has the prior adapter contract and returns. Failure result propagation depends on that return. | Recheck the encoded record and exhaustive adapter bank; establish actual cached-lock identity and ownership separately. |
| VO8 | Failure retention statements concern the captured sequential caller suffix. They do not assume whole-program serialization or cleanup. | Trace external callers, concurrent writers, reset/free paths and the outer response before assigning native lifecycle meaning. |

## Bounded continuation

| Impact | Further question | Required evidence |
| --- | --- | --- |
| High | How does `0xfffffe000a51b9d8` complete each element and advance the index? | Source continuation, loop bounds, further field writes and final release; only first index zero is established here. |
| High | Which native allocator outcomes are admissible for these two views? | Matching allocator/zone initialization, runtime links, flags and returns; static null branches alone do not answer this. |
| High | Does one writer lock epoch serialize publication with vault/allowed readers? | Actual lock identity, pointer/tag epochs, concurrent writer census and reclamation discipline. |
| Medium | What do the 512 B element's fields and constants mean? | Their downstream readers and transformations; site labels and constant resemblance do not identify the algorithm. |
| Medium | How does startup failure reach daemon-facing status or retry behavior? | Named-method forwarding, outer cleanup and exact transport fields in a matching execution. |

## Reproduction and quality gates

Run `recover_lskd_vector_origin.py --verify` with `triage_evidence` on the Python module path and Z3 available. It recaptures the original bytes, banks, descriptors, slots and retained frame epochs; re-lifts the source slices; and compares the complete logical artifact. The publication audit reparses all sixteen serialized queries, verifies the owned manifest delta and original inputs, and scans raw and decompressed owned files. Substantial JSON artifacts are stored as verified Zstandard archives. Repository reports updated in this increment use portable interpreter commands and remove analyst-machine path literals.

Extraction costs O(B+I+E+256R) time and storage for consumed bytes B, instructions I, retained epochs E and bank rules R, plus pointer-chain decoding. Source lifting constructs O(I) expression nodes; solver cost is separate, with a 10 s query limit. The fixed local initialization has 47 typed stores and a 164 B write union. No target timing, native resource bound or full-object initialization is inferred.

- **QG1** passes for factual interface and source analysis.
- **QG2** passes with VO1-VO8, dependent results and falsification probes.
- **QG3** passes for vector origin, typed allocation labels/extents, first element/tag writes and the conditional vector-failure release/result suffix. The full cross-layer objective remains active.
- **QG4** passes with explicit u32/u64 modular arithmetic, byte widths, source offsets and declared/indexed extents.
- **QG5** passes with distinct frame fields, allocator versus fresh-load predicates, partial initialization, conditional null outcomes and unknown native epochs.
- **QG6** passes with original bytes, site strings, pointer chains, exact allocator symbols, retained frame producers and sixteen checked mismatch queries.
- **QG7** passes with impact-ranked loop, allocator, synchronization, field-consumer and transport questions.
