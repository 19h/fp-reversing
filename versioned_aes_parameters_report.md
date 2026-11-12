# Selector-21 AES parameters, partial initialization and startup lock interface

The clear-bit selector-21 path now has separate source continuations for a declared successful 104 B allocation and a counterfactual NULL return. Success defines 31 B of `site.FPAESParameters`, constructs a 32 B table-derived local constant, and stops before reading the startup lock-pointer cell. A separate arbitrary-lock-word continuation packs request `0x729` and reaches private wrapper `0xfffffe000a5b403c`, with the parameter pointer retained in X28. NULL produces record result `0xce515a38`, returns through the inner routine and adapter with zero exported stack delta, and stops before output-stream free. No allocator, lock API, hardware operation or native IPC executes. [AP1-AP7]

```text
unchanged flag-0 allocation frontier: site.FPAESParameters, 104 B
  |
  + declared distinct return H3
  |    -> original control stores + original 16 B fill
  |    -> 31 B source-defined / 73 B undefined in retained epoch
  |    -> construct 32 B local constant from original image table
  |    -> STRICT STOP before startup lock-cell read
  |         |
  |         + separate arbitrary lock-word continuation
  |             -> private {lock word, encoded request} record
  |             -> matching decoder gives request 0x729
  |             -> STOP before wrapper 0xfffffe000a5b403c
  |
  + counterfactual NULL return
       -> write A+0x270 = NULL
       -> C+0x20 = 0xce515a38
       -> inner return -> adapter delta 0
       -> reverse overwrite H2[32 B]
       -> STOP before output-stream free
```

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| AP-A1 | The pinned KC, normalized image and transitive receipts identify the source build and retained epochs. All joins depend on them. | Rehash dependencies, reproduce all eight reaching prefixes exactly, and compare original instruction words and chained pointers. Native build pairing remains unknown. |
| AP-A2 | The existing flag-0 and arbitrary auxiliary/guard premises remain unchanged. Success supplies a fresh, valid, disjoint 104 B object H3; NULL is a counterfactual return. Allocation continuations depend on these declarations. | Preserve both earlier receipts exactly, clobber X1-X18 independently, supply no allocator memory effects, and audit strict source-defined masks. Native allocation/failure feasibility remains unknown. |
| AP-A3 | Ordinary callee-saved registers/SP and abstract PAC source transfers describe the call-return model. Pointer lineage and returns depend on these semantics. | Check source call stack, original authenticated slots/modifiers, return SP equality and source byte equations. Native authentication/fault behavior remains unknown. |
| AP-A4 | Record, streams, workspace, auxiliary memory, frames, controllers and H3 have the retained valid disjoint extents. Memory equations depend on these premises. | Two placements/global epochs, exact read/write byte epochs, and rejection of undefined private reads or escaped stores. A pointer inequality does not establish native ownership. |
| AP-A5 | A separate continuation may represent the startup lock-cell contents by arbitrary u64 `startup_lock_cell64`. The 47-visit lock-record continuation depends on it. | Keep the strict read frontier intact. Copy only the exact unchanged word to the one recovered record field; require all selected control/address/call observables to remain concrete. Do not assume non-NULL, valid IOLock identity, ownership or source startup continuity. |
| AP-A6 | Existing initializer/startup receipts provide static context for the shared global addresses. The lifecycle cross-reference depends on their pinned evidence. | Hash both retained check artifacts and recapture the original startup stores. Their private model lock identities and later replacements are separate from this allocation epoch. No native epoch join is asserted. |
| AP-A7 | Local A64 post-index stores, CBZ/CBNZ, UBFX, byte loads and SUBS equality semantics cover the newly selected instructions. Source conclusions depend on this lift. | Fresh extraction, seven UNSAT equations, one exhaustive 256-input bank identity, original-word comparisons and independent byte epochs. Full helper/inner/native semantics remain unknown. |

## Reaching allocation and pointer lineage

The [inner-entry report](versioned_inner_entry_report.md) stops before `_IOMallocTypeImpl` at `0xfffffe000a69d8f0`, X0 type view `0xfffffe000847b460`, name `site.FPAESParameters`, flags `0x64`, size 104 B. The new producer reproduces every prior strict prefix and flag-0 continuation exactly before adding a return premise. No earlier receipt or allocator model changes. [AP1-AP3]

Let H1 and H2 be the existing 32 B input/output stream objects. Success declares H3=H1+`0x400`=H2+`0x200` in the private model. This places a distinct 104 B span within the declared guest extent. All 104 B start without a source definition; no zero fill or allocator metadata is supplied. X0 is H3 or NULL, X1-X18 are independent arbitrary u64 clobbers, and LR is the pending call's return PC. [AP2-AP4]

Under the retained W19=`0x34e`, W22=`0xd71`, the original return gate at `0xfffffe000a69d92c..0xfffffe000a69d948` has this universal pointer equation: [AP3,AP5]

| Returned X0 | Table index | Source target of transfer at `0xfffffe000a69d950` |
| --- | --- | --- |
| Non-NULL | `0xd71` | `0xfffffe000a69d954` |
| NULL | `0xd80` | `0xfffffe000a69de64` |

The gate first clears X28. The successful target then copies X0 to X28 at `0xfffffe000a69d958`. That pointer remains H3 at the strict lock-cell frontier and the later pending lock-wrapper call. No claim that the parameter object has already been consumed by a preparer or coordinator follows. [AP3-AP5]

## Exact 104 B initialization coverage

The original control stores at `0xfffffe000a69d960..0xfffffe000a69d974` establish the following fields. The new source equation quantifies over arbitrary H3, subject to the memory premises. [AP3,AP5]

| H3 byte offset | Width, B | Value | Original store / effect |
| --- | ---: | --- | --- |
| `0x00` | 1 | 1 | `0xfffffe000a69d960` |
| `0x01` | 1 | 1 | `0xfffffe000a69d964` |
| `0x12` | 16 | Zero bytes | Original fill helper, called at `0xfffffe000a69d9c0` |
| `0x24` | 4 | 0, little-endian u32 | First lane of STP at `0xfffffe000a69d970` |
| `0x28` | 4 | `0x1000`=4,096, little-endian u32 | Second lane of the same STP |
| `0x2c` | 4 | 0, little-endian u32 | `0xfffffe000a69d974` |
| `0x38` | 1 | 0 | `0xfffffe000a69d968` |

Call `0xfffffe000a69d9c0` selects pure helper `0xfffffe000a687d64` through original slot `0xfffffe000847a670`, IA diversity `0x46ae`, with X0=H3+`0x12`, W1=0, X2=16 B. Its original body executes in the source lift; no host memset or blanket heap initialization substitutes for it. The helper's alignment head is `min_unsigned(count, (-low32(pointer)) & 7)`, independently source-proved. For these H3 placements, six leading byte stores, one 8 B store and two trailing byte stores cover exactly 16 B. [AP3-AP5]

Unique defined intervals are `[0,2)`, `[18,34)`, `[36,48)`, `[56,57)`, in bytes. Coverage is `2+16+12+1=31 B`; remaining coverage is `104-31=73 B`. Undefined intervals are `[2,18)`, `[34,36)`, `[48,56)`, `[57,104)`. No parameter-object read occurs before the retained frontier. Undefined retained source bytes do not establish native uninitialized memory. [AP3-AP4,AP7]

The earlier [packed-carrier report](carrier_control_report.md) isolated the same control stores without allocation lineage. This increment supplies their actual reaching source path under AP-A2. Its 104 B reset operation is a separate operation: that reset clears 95 B and preserves 9 B. It does not imply that the present fresh-object construction defines 95 B. [AP2-AP4]

## Table-derived local constant

Before the lock read, the original 32-iteration loop at `0xfffffe000a69da0c..0xfffffe000a69da80` writes W+`0x118` through W+`0x137`. An exhaustive 256-input original bank identity selects pool slot `0xfffffe0008472d08`, whose chained pointer targets `0xfffffe0007949dab`. The loop uses `LDURB [pointer+index-4]`, so its 32 original source bytes begin at `0xfffffe0007949da7`. These are image data, distinct from input-B and parameter bytes. [AP3-AP6]

For the retained phase `0x78c`, the byte equation reduces to:

```text
local[j] = image8[0xfffffe0007949da7+j]
           XOR ((-19*j) mod 256) XOR 0x95,  0 <= j < 32

local[32 B] = ab673d215061a15271372b7a59ba3513
              1b97ed918011110281e78f02086f65e3
```

The arithmetic/store equation is independently quantified over arbitrary source byte, phase and index; the stated 32 B value is a finite retained result. Its later role as key material, plaintext or another cryptographic input is unknown. The loop does not write these bytes into H3 or output-B. [AP3-AP6]

## Startup lock frontier and private operation record

The strict successful continuation adds 1,082 source visits and stops before `LDR X9,[X9]` at `0xfffffe000a69da98`, address `0xfffffe000cccda78`, width 8 B. This cell lies in this image's `__DATA,__common` zero-fill section. The normalized reader has no file-backed bytes for it; no runtime zero, lock identity or reaching startup value is inferred. [AP3-AP4,AP7]

Existing [initializer evidence](kext_provider_initialize_report.md) identifies `0xfffffe000a607230` as the writer of this lock-pointer cell. In its first and cached initialization cases it publishes distinct model lock identities L3 and L7. The [startup/hardware bridge evidence](kext_startup_hardware_bridge_report.md) separately uses that cell's lock in its constructor path. These source facts establish a shared architectural touch point. They do not join the private initialization and selector-21 models into one native lifetime. [AP6-AP7]

The same startup range writes zero to environmental byte `0xfffffe000ccca078` at `0xfffffe000a607218`. Thus an earlier static writer of the preceding report's flag is already present in the repository. Its complete writer set, warm transition, runtime domain and concurrency remain unknown; this increment still uses the earlier declared stable flag-0 fixture. [AP6-AP7]

The separate continuation retains an arbitrary `startup_lock_cell64` and copies it unchanged to K=W+`0x160`. It adds 47 visits and reaches pending call `0xfffffe000a69db54` to `0xfffffe000a5b403c`, original slot `0xfffffe000847a668`, IA diversity `0x46ae`, X0=K. That wrapper's body is not entered by this continuation. [AP3-AP5]

| Private record field | Recovered contract |
| --- | --- |
| K+0, u64 | Exact arbitrary startup lock-cell word |
| K+8, u32 | Encoded request |
| Key | `key=(low32(K) XOR 0x6133a0c8)*0x84d77373 mod 2^32` |
| Matching decoder | `request32 = encoded32 + key mod 2^32`; X0 becomes the lock word |
| Retained request | `0x78c-0x63 = 0x729` |
| X28 at pending wrapper | H3, unchanged from the successful return |

The source pack equation at `0xfffffe000a69da9c..0xfffffe000a69db00` and matching wrapper decoder at `0xfffffe000a5b412c..0xfffffe000a5b414c` quantify over arbitrary record address, phase and lock word. This confirms the internal record ABI. Request-specific lock behavior, NULL handling and the subsequent parameter consumer remain outside the composed path. The arbitrary word is not treated as a Mach port or established live IOLock. [AP3,AP5-AP7]

## NULL result, auxiliary update and return channels

The counterfactual NULL cases add 1,169 source visits each. They take the relative-table index-0 path, store X28=NULL to A+`0x270` at `0xfffffe000a69b228`, and derive W25=`0xce515a38` at `0xfffffe000a69b260`. Store `0xfffffe000a69d834` writes that value to C+`0x20`. The earlier flag-1 error instead wrote `0xce515b53` to an input-stream status field before relaying it. These are different source paths and encoded results. No business error name is assigned. [AP3-AP5]

All eight NULL paths preserve the private header, pass the coherent source guard comparison, and return through the inner routine and adapter with zero exported delta. The caller then overwrites all 32 B of H2 in reverse order. Pending free at `0xfffffe000a5a92e4` has type view X0=`0xfffffe000847bba0`, object X1=H2. No 104 B object exists in the NULL premise, no H3 byte is source-defined, and no free body or later copyback executes. [AP3-AP4,AP7]

Neither successful nor NULL continuations read additional input-B bytes, write output-B bytes, transfer a task/right, or emit a new Mach message. The parameter object, local constant and lock-operation record are private kernel-side interfaces in this analysis. Actual daemon/kext task, connection, build and native ownership pairing remain unknown. [AP3-AP4,AP7]

## Provenance and validation

| ID | Primary evidence |
| --- | --- |
| AP1 | Original KC SHA256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized kext `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. New source words, pointer chains and data are original-byte checked. |
| AP2 | Parent receipt SHA256 `9337520390e93eb413f513e495bd85b65fc9601656abb495304ddaf4fa4aae4c`; exact fresh prefix/flag-0 equality precedes each new allocation model. |
| AP3 | [Extractor/source lift](triage_evidence/recover_versioned_aes_parameters.py): distinct/null returns, no allocator fill, original fill helper, strict external read and separate arbitrary-lock continuation. |
| AP4 | [Compressed receipt](triage_evidence/versioned_aes_parameters_checks.json.zst): 16 allocation continuations and eight separate lock-origin continuations; 18,384 retained visits, 15,304 read bytes, 3,128 write bytes, 584 authenticated transfers and 24 returns. Repeated reaching prefixes are excluded from these totals. |
| AP5 | Seven UNSAT source queries / 61 lifted instruction instances: NULL gate, control stores, fill head, lock record pack and matching decoder, NULL status and local-constant byte equation. |
| AP6 | Exhaustive 256-input constant-bank identity, original chained source pointer and 32 image bytes; hashed initializer and startup/hardware check artifacts; freshly captured original startup store instructions. Older startup models are referenced, not rerun or joined natively. |
| AP7 | [Publication verifier](triage_evidence/verify_versioned_aes_parameters_publication.py): fresh extraction/proofs, independent byte epochs and snapshots, 31 B coverage, preserved originals, exact publication delta and decoded-path hygiene. Original files suffice; no new IDA access or native execution is required. |

The complete new interval is bounded at 10,000 steps/case. Extraction and byte audit use O(receipt bytes+C*V+I) time/space, plus solver cost capped at 30 s/query. Original prefix reproduction is explicit additional work. The evidence is reproducible using the pinned project dependencies; large JSON receipts and the manifest are published as losslessly roundtripped zstd level-22 archives.

The independent byte audit checks 18,384 original source words, 15,304 read bytes (224 symbolic), 3,128 write bytes (64 symbolic), 584 authenticated edges and 6,976 snapshot bytes. Its new symbolic writes are the eight exact lock-word copies; allocator-return premises do not initialize memory. [AP4,AP7]

| Impact | Further bounded work | Required evidence |
| --- | --- | --- |
| High | Compose the private lock-operation wrapper and reach H3's actual consumer. | Request `0x729` decoding, actual NULL/non-NULL routing, original lock call and return contracts, and preserved H3 lineage. |
| High | Join startup and selector-21 global lifetimes. | Actual lock publication/replacement, warm-byte transition, synchronization and matching native epoch; shared addresses alone are insufficient. |
| High | Establish all fields required by the later parameter consumer. | First reads of the 73 undefined source bytes, intervening stores/reset, and actual allocator initialization contract. |
| High | Finish cleanup and selector-21 result/copyback. | Remaining original free/return contracts, status preservation and UserClient size/status gating. |
| High | Establish native daemon/kext exchange pairing. | A matched build/task/connection/right and transaction epoch; historical failed-open trace and private source models remain separate. |
| Medium | Determine the local 32 B constant's semantic role. | Reaching data flow into the actual preparer/coordinator/provider interface; byte appearance alone does not identify a cryptographic role. |

- **QG1**: Pass. Factual source, ABI, lifecycle and control-flow analysis requires no normative content.
- **QG2**: Pass. AP-A1..AP-A7 identify assumptions, dependent results and falsification probes.
- **QG3**: Pass for this increment. Allocation lineage, exact partial initialization, local constant, startup touch points, lock record and separate NULL return are covered. The full goal remains active.
- **QG4**: Pass. Widths, byte intervals, u32 wrapping, `31+73=104 B`, 32 byte-loop iterations and retained/reproduced visit accounting are explicit.
- **QG5**: Pass. Fresh construction/reset, source-defined/native initialization, strict/symbolic continuations, separate error results and private/native resource epochs remain distinct.
- **QG6**: Pass. Original bytes/chains, pinned receipts, seven source equations, exhaustive bank identity and independent epochs provide scoped provenance.
- **QG7**: Pass. Lock/consumer, global lifetime, field coverage, cleanup, native pairing and constant-role work is bounded and impact-ranked above.
