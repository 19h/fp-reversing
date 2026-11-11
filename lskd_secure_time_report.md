# LSKD SecureTime publication, embedded RW and clock-query interface

The post-population helper `0xfffffe000a52f728` is exactly `BTI C; RET`: an eight-byte compiler-bounded no-op. It does not consume the completion record or construct another object. The later zero-presence continuation allocates a 64 B `site.LSKDSecureTime` object and publishes its raw pointer into cell `0xfffffe000ccc78c0` before checking the result. Its nonnull branch constructs an RW lock at object `+0x18`. Both the object-allocation null arm and the nonzero constructor-status arm select the common raw-success return `0x5e561849`. Raw success therefore does not establish a fully initialized SecureTime object. These are conditional source statements; native failure admission, execution and ownership remain **unknown**. [ST1-ST6]

Constructor success prepares acquisition of the embedded RW pointer, writes a self-reference and a seed-derived qword, requests four random bytes at object offset zero, then requests a four-byte read of `kern.monotonicclock` through exact kernel `_kernel_sysctlbyname`. The later [clock-completion report](lskd_clock_completion_report.md) recovers that consumer's exact field formulas, explicit unlock and common raw-success source return. It also identifies the conditional AppleSPMIPMU seconds OID and nominal tick projection. Native clock availability/calibration, lock balance, object/free lifetime and daemon-facing completion remain **unknown**. [ST3-ST8]

[Original source and checked queries](triage_evidence/lskd_secure_time_checks.json.zst), the [extractor](triage_evidence/recover_lskd_secure_time.py) and the [publication audit](triage_evidence/verify_lskd_secure_time_publication.py) retain eleven kext spans / 348 instructions / 1,392 B, twenty-eight operand anchors, seven exhaustive banks / 1,792 inputs, six authenticated continuation slots and thirteen retained frames with eighteen fields each. Nineteen UNSAT queries cover 159 source-lifted instruction instances. No new target, allocator, synchronization, entropy, sysctl or IDA execution occurred.

```text
population exit -> prepared completion record -> A52F728: BTI C; RET
  -> raw success -> release cached LSKD RW -> fresh CCC78C0 load
       nonzero -------------------------------> raw-success return
       zero -> typed allocation, 64 B
                 -> CCC78C0 = allocation result
                 null ------------------------> raw-success return
                 nonnull P -> P+18 = 0
                            -> construct RW, destination P+18
                               nonzero status -> raw-success return
                               zero status -> explicit RW acquisition
                                 -> P+8 = P; seed-derived qword at P
                                 -> read_random(P,4)
                                 -> sysctl("kern.monotonicclock",...,4,...)
                                 -> A51C0E0 [fields and explicit unlock; later report]
```

Diagram offsets are hexadecimal and addresses abbreviate prefix `0xfffffe000`. Each returning call and pointer reload requires the frame, object and publication epochs below. A source acquisition request does not establish native lock ownership.

## Provenance and the no-op boundary

Original KC SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized kext SHA-256 is `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Every captured instruction is byte-compared between them. Each resolved slot is independently checked against original chained-format-8 membership, target and authentication diversity. Hardware authentication is unexercised. [ST1]

The supplied C already identifies `sub_FFFFFE000A52F728` as `[empty]` at line 4366. Its kext `LC_FUNCTION_STARTS` bounds are `0xfffffe000a52f728..0xfffffe000a52f730`, within UUID `227f9df7-645d-39b8-b74a-685303d16b4b`. The exact eight bytes are `5f2403d5c0035fd6`, SHA-256 `d33fdb74881bcff46b1cf4fc3e20479b1882e0e683789e80e6d650554066a1aa`. They decode only to `BTI C; RET`; neighboring instructions belong to the next compiler entry. [ST1-ST2]

The preceding [population report](lskd_element_population_report.md) resolved call `0xfffffe000a56e9e4` through slot `0xfffffe0008471450`, diversity `0x6e7d`. That resolution is rechecked here. The selected callee performs no data-memory access, nested call or GPR write; it returns through X30 with X0 unchanged. The prepared encoded word and four pointer arguments therefore have no consumer in this callee on this build. The original caller still performs their stores and subsequently supplies raw success. No phase decoder or hidden object construction should be assigned to these eight bytes.

Supplied C lines 39705-39815 corroborate typed-allocation publication and its null gate; lines 42416-42501 corroborate destination object `+0x18`, the constructor record and status gate; lines 81431-81534 retain self-reference, seed and entropy arguments; lines 20816-20932 retain the clock name, five arguments and name-buffer clear. Original instructions resolve the obfuscated banks and precise register contracts. The three original reference inputs remain unchanged; no IDA lookup was needed.

## Frame roots, typed view and publication order

The same thirteen retained start prefixes stop before their earlier entropy call. Reconstructing ordered byte writes establishes eighteen fields per frame, through fifteen distinct original producer PCs. This reuses finite recorded prefixes; the new suffix never executes. Persisting those fields to the new source joins remains ST3. [ST1,ST3]

| SP offset | Value or role |
| --- | --- |
| `+0x10` | SecureTime pointer cell `0xfffffe000ccc78c0` |
| `+0x78`, `+0x80` | Flag cell `0xfffffe000ccc78e0`; seed-pointer cell `0xfffffe000ccc78b8` |
| `+0xb0/+0xb8` | Constructor bank B |
| `+0x108/+0x110` | Clock-query bank D, right/left respectively |
| `+0x120`, `+0x128` | Scratch SCR=W`+0x80`; reused record R=W`+0xa8` |
| `+0x150/+0x158` | Completion/acquire/random bank C |
| `+0x168/+0x170` | Type-view bank E |
| `+0x178/+0x180` | Controller cells `0xfffffe000ccc2d90`, `0xfffffe000ccc2c60` |
| `+0x188/+0x190` | Allocator bank A |
| `+0x198` | Common result receiver W`+0x40` |

At entry `0xfffffe000a5268dc`, incoming W9=`0x1fb` reduces to saved W19=`0x30c`, W20=`0x3be`. The allocator rule selects exact `_IOMallocTypeImpl` at `0xfffffe000c4ba154`. The type rule selects pool slot `0xfffffe0008471c78` whose original target is view `+4`; `SUB X0,X8,#4` supplies view `0xfffffe000847aea0`. Its original pointer fields decode to the normalized name/signature pointers. [ST1,ST3-ST4]

| Typed-view field | Recovered value | Evidence boundary |
| --- | --- | --- |
| Name pointer `+0x10` | `0xfffffe000791dcb0`, `site.LSKDSecureTime` | Original chained pointer and twenty matching name bytes |
| Signature pointer `+0x20` | `0xfffffe00079202e0` | First eight bytes `3231323132323231`; deeper type meaning unassigned |
| Flags u32 `+0x28` | `0x64` | Source metadata, no inferred zeroing guarantee |
| Declared size u32 `+0x2c` | 64 B | Descriptor size, actual native backing unknown |
| Leading sixteen file bytes | Zero | Runtime linkage/registration epoch unknown |

At call `0xfffffe000a526984`, X0 is this view. On return, `0xfffffe000a52698c` stores X0 into the global cell, including a possible zero. Only then does the source test X0. No Mach port is produced by this store; the published value has allocator-result provenance.

| Source outcome | Dispatch index / target | Raw result behavior |
| --- | --- | --- |
| Allocation result zero | `0x30c` / `0xfffffe000a52e4b0`, diversity `0x0343` | W8=`0x5e561849`; common store at receiver `+0x38`, then frame return |
| Allocation result nonzero P | `0x35b` / `0xfffffe000a528a0c`, diversity `0x0343` | Enter embedded constructor |

The allocation-null arm contains no new object dereference before the common return. Its source result is established independently of whether the matching allocator can return null under actual native metadata and policy. Raw success is the existing internal word; this increment does not establish a successful outer method or transport response. [ST4,ST6]

## Embedded RW construction and status gate

The nonnull arm first writes qword zero at P`+0x18` at `0xfffffe000a528a2c`. It then reuses R=W`+0xa8` for the already recovered [RW constructor](lskd_lock_origin_report.md):

```text
u32(x) = x modulo 2^32
constructor_key = u32((low32(R) XOR 0xAE0701E7) * 0x952F3CB7)
R.u32[0] = constructor_key + 0x90D
R.u64[+8] = P + 0x18
constructor writes status32 at R + 0x10
```

The original bank selects `0xfffffe000a552490`, slot `0xfffffe0008471600`, diversity `0x86eb`, at call `0xfffffe000a528ac0`. The earlier constructor evidence establishes that selected phase `0x90d` uses its supplied destination. `IORWLockAlloc` nonnull results are stored there with status zero; null allocation yields `0xffff5964` and skips the destination store. Here the caller has already cleared the destination. Null destination has separate status `0xffff5966`; a valid 64 B P makes P`+0x18` an accessible, nonnull destination. Native object and lock validity remain ST4-ST5.

The source's encoded comparison is universally equivalent to `status32 == 0`, rather than merely matching selected examples. It has these continuations:

| Constructor status | Index / target | Established local effect |
| --- | --- | --- |
| Zero | `0x32c` / `0xfffffe000a55e334`, diversity `0x2984` | Begin embedded-lock acquisition preparation |
| Any nonzero u32 | `0x1fb` / `0xfffffe000a52e4b0`, diversity `0x2984` | Supply raw success and return through receiver `+0x38` |

No clear of the published P, free of P or alternate raw word appears on this direct nonzero-status suffix. Under the constructor's null-allocation result and matched storage epoch, P remains published with embedded RW cell zero. This is a source partial-initialization contract; native occurrence and subsequent consumer admission remain unknown. [ST3-ST6]

## Explicit acquisition, field writes and entropy interface

Source `0xfffffe000a55e338..0xfffffe000a55e39c` freshly reloads P from the global, then its lock pointer from P`+0x18`. It overwrites R with a different twelve-byte acquisition record:

```text
acquire_key = u32((low32(R) XOR 0x1D65DAD0) * 0xE9655F4D)
R.u64[0] = reloaded_P.u64[+0x18]
R.u32[+8] = acquire_key + 0x2D2
```

Call `0xfffffe000a55e3e0` selects acquisition adapter `0xfffffe000a54e220`, slot `0xfffffe0008471190`, diversity `0x560f`. The [existing adapter contract](lskd_continuations_report.md) uses the explicit pointer when nonnull and can otherwise fall back to cached cell `0xfffffe000ccc78a8`. Under the constructor-success and stable-publication premises, the new caller supplies the embedded pointer explicitly, extending that adapter beyond its earlier null-explicit callers. This distinguishes three source lock domains: global LSKD RW cell `0xfffffe000ccc78a8`, sample-processing cell `0xfffffe000ccceab8`, and the new object member P`+0x18`. It does not establish three simultaneous native lock objects. [ST3-ST5]

After a returning acquisition call, the source reloads P again. The selected writes and next request are:

| PC | Destination / argument | Source meaning |
| --- | --- | --- |
| `0xfffffe000a55e3e8` | P`+8`, u64 | Self-reference P |
| `0xfffffe000a55e424` | P`+0`, u64 | `(seed_qword & 0x7fffffffffffffff) XOR 0x23c7e4b4853b50c4` |
| `0xfffffe000a55e46c` | X0=P, W1=4 | Four-byte random-output request |

Under preceding flag 255 and seed pointer T=`0xfffffe000ccc78f4`, the signed flag load followed by mask `0xffffffffa7d93298` selects byte offset `0x98`=152. The qword therefore comprises seed u32 indices 38 and 39 in little-endian order. Neither index is one of the preceding sixteen edited indices 0,4,...,60. Its contents remain opaque. The bit-63 clear and XOR are explicit source operations; no time value or standardized cryptographic role is inferred. [ST7]

The entropy bank selects wrapper `0xfffffe000a508d6c` through slot `0xfffffe00084714a8`, diversity `0x6e7d`. Original stub `0xfffffe000a69f394` loads import slot `0xfffffe000847c4f8`, whose exact kernel target is `_read_random` at `0xfffffe000be57d68`. Four bytes are requested at P, overlapping the lower half of the preceding qword. Actual returned bytes and backend behavior remain unknown. The caller makes no intervening result test before the clock-preparation continuation `0xfffffe000a511804`, selected by index `0x5b7`, diversity `0x40d9`. The later [clock-completion report](lskd_clock_completion_report.md) recovers the embedded-pointer release preparation after the clock-dependent field writes; native ownership and free remain unknown. [ST3,ST5,ST7-ST8]

## Clock query ABI and result handoff

The clock block writes zero to scratch SCR`+0x94` as u32, sets the stack's 64-bit length cell to 4, then writes the string `kern.monotonicclock` with its terminator plus one extra zero: 21 byte stores at SCR`+0x104..+0x118`. This is a source name construction. The selected query is a named kernel interface, not a Mach-message emission. [ST1,ST3,ST8]

| Call-site register at `0xfffffe000a511918` | Source value / role |
| --- | --- |
| X0 | SCR`+0x104`: NUL-terminated name |
| X1 | SCR`+0x94`: prezeroed four-byte output location |
| X2 | SP`+0x1d8`: pointer to u64 length initially 4 |
| X3 | Zero: no new-value pointer |
| X4 | Zero: new-value length zero |

The exhaustive bank selects wrapper `0xfffffe000a508d74` through slot `0xfffffe0008471508`, diversity `0x6e7d`. Its branch reaches stub `0xfffffe000a69f3b4`, which uses import slot `0xfffffe000847c508`. Original chaining resolves that slot to `0xfffffe000c2de71c`, with exact kernel aliases `_kernel_sysctlbyname` and `_sysctlbyname`.

On a returning call, ten u16 stores clear the first twenty name-buffer bytes; the separately zeroed twenty-first byte is not rewritten. `0xfffffe000a51194c` reloads the four-byte output into W15 while preserving X0's returned value through the inspected suffix. The source does not reload the returned length or branch on the status in this block. It retains the original target loaded from index `0x4b` and branches to `0xfffffe000a51c0e0`, diversity `0xf24b`. The later [clock-completion report](lskd_clock_completion_report.md) establishes that this consumer writes the new fields without a local status/returned-length gate, then prepares explicit unlock and raw-success source return. Its provider analysis identifies a four-byte seconds projection under the matched nominal OID/vtable premises. Requested width alone still does not establish physical calibration, successful output or a secure-clock algorithm. [ST8]

## Assumption register

| ID | Assumption and dependent results | Stress test or falsification probe |
| --- | --- | --- |
| ST1 | Original KC and normalized kext identify the pinned build. Address, bank, type and symbol claims depend on it. | Rehash both; compare every selected instruction/table; decode original chains and exact nlist matches. |
| ST2 | Compiler-start metadata bounds the selected no-op, and ordinary returning-call execution applies. Its zero record accesses and unchanged X0 depend on those eight bytes. | Reparse the full start catalog, check the next start and all bytes; establish native authentication/control transfers separately. |
| ST3 | Thirteen retained frame epochs persist through the declared returning calls; fresh global loads refer to a coherent object epoch. Composed paths depend on it. | Reconstruct last byte writes and source PCs; enumerate intervening writers, aliases and native entry/frame/publication changes. |
| ST4 | A nonnull returned P has at least 64 accessible bytes; the typed metadata is admitted by native allocation. Field safety and successful construction depend on it. | Establish allocator policy/outcomes and runtime type registration/backing. Keep file-zero links separate from initialized metadata. |
| ST5 | The earlier constructor/acquisition contracts apply to these source-produced phases and destination/lock pointer. Native ownership requires further evidence. | Recheck dependency hashes and constructor queries, recover all helper writes/calls and match actual construction/acquisition/release identities. |
| ST6 | The common source return is interpreted only as its raw word and receiver store. No outer semantic success is assumed. | Trace outer normalization/transport and admission of partially initialized objects; establish whether native null returns occur. |
| ST7 | The published flag=255 and seed-pointer epoch reaches the new load; random effects remain limited to the established API contract. The seed-index and overlap statements depend on it. | Recover all flag/seed/object writers and actual entropy call effects; retain unknown seed and returned bytes. |
| ST8 | Returning entropy/sysctl calls preserve the declared frame and callee-saved registers. Clock argument/result handoff depends on it. | Recover the selected OID/handler, output-size and status behavior, the next consumer and embedded-lock retirement; verify native availability separately. |

## Bounded continuation and scoped quality gates

| Impact | Next question | Evidence required |
| --- | --- | --- |
| High | How do later SecureTime readers admit the stored clock/seed relations? | The clock-completion report now resolves this source writer and explicit unlock; follow field consumers and matched epochs. |
| High | Is the recovered AppleSPMIPMU OID/provider actually selected and calibrated? | The clock-completion report now captures the original OID, registration, seconds handler and nominal vtable; native traversal and hardware evidence remain required. |
| High | What do later consumers require from a published P with a zero embedded lock? | Complete producer/consumer/retirement census, allocator failure admission and native publication/ownership epochs. |
| High | How do these objects feed a daemon-facing transaction? | Matching request, output serialization and IPC ownership with source and native evidence kept distinct. |
| Medium | Are the seed-derived upper bytes retained after the four-byte random request? | Complete entropy-write contract and subsequent field readers/writers; overlap alone does not prove final contents. |

Run `recover_lskd_secure_time.py --verify` with `triage_evidence` on the Python module path and Z3 available. It re-extracts original bytes, bounds, chains, banks, typed fields and frame epochs; re-lifts the selected scalar slices and compares the logical artifact. The publication audit independently re-solves all nineteen serialized queries plus the eighteen retained constructor queries, checks exact manifest ownership, source excerpts, original inputs and analyst-path hygiene. Substantial JSON is retained as verified Zstandard archives. No target operation or IDB mutation is required.

Extraction costs O(B+I+E+256R) time/space for source bytes B, instructions I, retained byte epochs E and bank rules R, plus chained-pointer work. Each source lift builds O(I) expressions; each solver query has a 10 s limit, with solver complexity separate. The new straight-line field/name work has constant source cost; native allocator/lock/entropy/sysctl complexity, latency and memory overhead remain unknown. All offsets and capacities are bytes; u32 arithmetic is modulo 2^32.

- **QG1** passes for factual interface and source analysis.
- **QG2** passes with ST1-ST8, dependent results and falsification probes.
- **QG3** passes for this increment's no-op boundary, SecureTime publication/constructor, explicit lock record, field/entropy preparation and clock-query handoff. The full goal remains active.
- **QG4** passes with exact u32/u64 widths, modular arithmetic, byte extents and requested output lengths; clock units remain unknown.
- **QG5** passes with native admission, source partial initialization, record reuse, fresh reload epochs and distinct lock domains explicit.
- **QG6** passes with original bytes, compiler starts, C excerpts, exact imports, exhaustive banks, retained producer epochs and checked queries.
- **QG7** passes with impact-ranked consumer, OID, lifecycle, entropy and cross-layer questions.

The [conditional stored-clock reader report](lskd_clock_reader_report.md) decodes the initialization relation, proves the zero-arm rewrite and recovers an exact unsigned fresh-versus-stored comparison. Fifteen UNSAT queries and two SAT controls qualify its phase/alignment and comparison contracts. Actual reader phase/frame roots, both helper-bank bindings, later admission/result and native daemon-kext lineage remain unknown.

The [elapsed high-water and continuation-record report](lskd_clock_accumulator_report.md) reduces the selected reader to a conditional unsigned elapsed high-water update. Thirty-four UNSAT certificates cover 754 lifted instruction instances; two SAT controls distinguish decoded-accumulator wrap from elapsed nondecrease and expose the missing signed-result range contract. Fresh embedded-pointer release preparation and a 40 B continuation envelope with 36 B locally written are recovered. Actual phase/frame roots, concrete helper targets, final context predicate, native epoch and daemon-kext lineage remain unknown.

The [context-comparison report](lskd_context_compare_report.md) corrects the continuation operand to the carry-flag XOR, recovers the complete comparison-record leaf and conditionally proves the final local gate: decoded accumulator < normalized context value and saved control low byte = 1. Twenty-two UNSAT certificates and two SAT controls cover the corrected handoff and carry-aware predicate. A 256-slot census retains three matching-diversity helper candidates; actual bank roots, saved phase, context/control producers and daemon-kext lineage remain unknown.
