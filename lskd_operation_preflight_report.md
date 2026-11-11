# Shared operation preflight, AES initialization and count branching

The shared body reached by original W1 values 1, 2, 4 and 5 first calls a `BTI; RET` stub, then a record wrapper around `initKernelAESHW()`. The first call consumes no record fields. The second wrapper writes the initializer's low32 result plus `0x06371ecc` at record `+4`. A nonzero low32 result takes the established context re-encoding/release path; conditional outer-result composition forwards the original numeric result unchanged. A zero result continues operation dispatch and does not establish completion of the selected operation. [PF1-PF8]

The continuing source saves the address of global `0xfffffe000ccc7848`, the earlier identified cached `getBytesNoCopy()` output cell. It also recovers original X2 and the low32 of original X4. Operations 1 and 5 compare that low32 value against unsigned thresholds 32 and 16, respectively; both arms continue. The subsequent [byte-span report](lskd_byte_spans_report.md) establishes byte units and short-copy versus full-split routing. The public operation meanings remain **unknown**. This joins the named wrapper to the shared accelerator-buffer facilities while retaining native lifetime, serialization, daemon-request and complete operation semantics as open questions. [PF2-PF8]

[Evidence](triage_evidence/lskd_operation_preflight_checks.json.zst), [extractor](triage_evidence/recover_lskd_operation_preflight.py) and [publication audit](triage_evidence/verify_lskd_operation_preflight_publication.py) retain 10 spans / 430 instructions / 1,720 B. Twenty-eight UNSAT queries cover 27 source pieces / 19,867 lifted instruction instances. Of these instances, 19,712 belong to seven source bank cuts, each enumerated over all 256 low-byte inputs with arbitrary upper24 bits. One SAT control separates a ready-bit test from validation of the cached pointer. No new native execution, IDA lookup, IDB mutation, Mach message or port-right emission occurs.

```text
original W1 = 1,2,4,5; working context decoded
  -> A52A7D8: context/op record -> A55C9C4: BTI; RET
  -> rewrite record+0 -> A5607E4: initializer-result record wrapper
       -> controller update -> A508030: initKernelAESHW()
       -> record+4 = low32(raw_result) + 06371ecc
  -> low32(raw_result) != 0
       -> index17 -> A527B24 -> re-encode -> cached RW release
       -> record result = low32(raw_result) [normal return and D=0 premises]
  -> low32(raw_result) == 0
       -> index979 -> A59B718 -> index849 -> A52A990
       -> save original X4 low32, original X2, address of CCC7848
       +-> W1=1,5 -> A535AD8 -> unsigned threshold 32,16; both arms continue
       +-> W1=2   -> A534758 [operation body remains open]
       +-> W1=4   -> A5238F8 [state144 consumer frontier]
```

Address suffixes and codes in the diagram are hexadecimal; thresholds 32 and 16 are decimal byte counts, as established by the subsequent byte-span evidence.

## Assumption register and primary provenance

| ID | Assumption / bound | Dependent claims | Stress test / falsification probe |
| --- | --- | --- | --- |
| PF1 | Pinned original KC and normalized image describe the selected build | Instructions, constants, pointer slots and named initializer | Rehash and compare every retained span, original chain entry and frozen initializer body; separately match a native image |
| PF2 | Named-wrapper phase `0x6e3`, saved outer record/key and post-flag frame roots reach this source template | Operation ancestry, original X2/X4 recovery and caller banks | Replay the reader-lineage and context-return certificates; match actual predecessors and frame epochs |
| PF3 | Exact u32/u64 scalar, extension, condition and address semantics apply | Record keys, controller update, status projection and count thresholds | Rebuild the fail-closed lift; replay queries and exhaustive byte cuts; inspect source comparison signedness |
| PF4 | Source frames and context are valid and separate from controller/global cells; protected frame cells survive returning calls | Record identity, saved phase and post-call data flow | Check actual addresses, alias writers and call effects; distinct source offsets alone do not establish native separation |
| PF5 | Referenced bank bytes and pointer roots retain their source identities | Constant targets for arbitrary controller-derived byte inputs | Recheck both 256-byte tables and original fixups; enumeration covers arbitrary upper24 bits but does not prove native root identity/PAC |
| PF6 | Initializer and nested APIs return and preserve the required callee-saved registers and caller-frame cells | Post-call routing, status forwarding and saved roots | Check callee effects, exceptions and aliases; the source wrapper does not establish successful provider initialization |
| PF7 | Prior re-encoding/release composition, normal guards/PAC and zero outer displacement D apply | Nonzero initializer result reaching outer W0 | Replay the prior conditional return contract and prove actual cursor preservation, lock epoch and return behavior |
| PF8 | Later operation bodies, native buffer invariants and upstream transport are outside the retained source cuts | Interpretation and completeness limits | Trace admitted continuations, pointer/count consumers, concurrent buffer users and actual daemon serialization |

Original KC SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized image SHA-256 is `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Retained bytes match both sources. Supplied C lines 44277-44390 corroborate the shared body and lines 83537-83573 corroborate its initializer wrapper. The complete initializer span matches the frozen [AES initialization/cleanup source](triage_evidence/aes_cleanup_epoch_source.json.zst); the supplied C names `initKernelAESHW`. Nominal `getBytesNoCopy()` binding comes from the [buffer lifecycle report](kext_buffer_report.md), not from guessing the obfuscated global's name. All three original supplied inputs remain unchanged. [PF1,PF3]

## Two calls and two record phases

Let R=caller FP`-0xb0`, P=`u64[caller SP+0x1f8]`, operation O=original W1, and Q=`u32((low32(R) XOR 0x69e35e3f)*0x7a59c441)`. The shared body builds a 16 B initialized record before the first call:

| Offset | Width | Source value | Original store |
| --- | ---: | --- | --- |
| `+0` | 8 B | P, working context pointer | `0xfffffe000a52a850` |
| `+8` | 4 B | `u32(Q+0x5d7334cb)` | `0xfffffe000a52a848`, first STP word |
| `+12` | 4 B | `Q XOR O XOR 0x0c529166` | Same STP, second word |

The pointer and record fields are source facts; they are not a recovered public struct declaration. The selected callee at `0xfffffe000a55c9c4` consists exactly of `BTI c; RET`. It neither loads the record nor modifies its contents. The associated BLRAA updates LR as part of the call; the callee's RET does not itself imply a cryptographic operation. [PF2-PF5]

| Call boundary | Source site | Bank result / original slot | Target and modifier |
| --- | --- | --- | --- |
| Context/op record hook | `0xfffffe000a52a8c0` | Index `0x9b5`, slot `0xfffffe00084711c8` | `a55c9c4`, diversity `0x560f` |
| Initializer record wrapper | `0xfffffe000a52a958` | Index `0xa01`, slot `0xfffffe0008471428` | `a5607e4`, diversity `0x6e7d` |
| Actual AES initializer inside wrapper | `0xfffffe000a56095c` | Index `0x9fd`, slot `0xfffffe0008471408` | `a508030`, diversity `0x86eb` |

After the no-op returns, source `a52a8c4..a52a90c` writes `u32(Q+0x4c88d07a)` into R`+0`. This four-byte store overwrites only the low half of the previous pointer. The upper half at R`+4` remains prior contents until the initializer wrapper writes its result there. R`+8` and R`+12` retain the earlier words at this source boundary, under the no-alias premise. The wrapper does not decode these input fields: it saves incoming X0 as its record pointer, performs its controller/call sequence, then writes the result at `+4`. Old R`+4` contents are not an input to that source store. [PF3-PF6]

## Controller update and initializer result projection

The wrapper selects distinct controller cells C=`0xfffffe000ccc2dd0` and B=`0xfffffe000ccc2c60`. With old 64-bit values c and b and wrapper body SP F, the original load/update pieces implement:

```text
T = u64((c XOR b) + F + 8)
new_C = u64((T - 0x6c627538298d3f88)*0xea5ebdeb)
new_B = u64((T XOR 0x6c627538298d3f88)*0xea5ebdeb)
```

The stores are `0xfffffe000a5608c4` and `0xfffffe000a5608c8`. The intervening bank-B root cut preserves the earlier C value/root and update constants. These are controller-state transformations; no clock, key or lock meaning is assigned to the cells. The wrapper shares B with the caller's controller family, making concurrent lifetime and serialization questions material. Arbitrary controller values still select constant targets through the exhaustive bank identities, provided the bank bytes and roots are stable. [PF3-PF6]

The wrapper's initializer call base is recovered through an original pool pointer to `TABLE+8`; source `a560950..a560958` applies the index and a compensating `-8`, selecting the exact initializer slot. This offset cancellation is part of the source ABI rather than an assumed table address. On normal return with raw X0=U64, source `a560960..a56098c` stores:

```text
private32 = u32(low32(U64) + 0x06371ecc)
u32[R+4] = private32
```

The MBA expression is proved for every low32 result. No instruction after that call assigns a new X0 before the wrapper's normal RETAB, so the record status and incidental raw return are separate source channels. The caller uses the record status: it loads W21 from R`+4` and compares it with `0x06371ecc`. The comparison is exactly `low32(U64)==0`, not a full-width X0 test. [PF3,PF6]

| Initializer low32 result | Private record result | Caller route | Conditional outer u32 result |
| --- | --- | --- | --- |
| Zero | `0x06371ecc` | `0x979 -> a59b718 -> 0x849 -> a52a990` | Later operation decides; zero preflight is not final success |
| Nonzero u | `u32(u+0x06371ecc)` | `0x17 -> a527b24` | u, under the prior return premises |
| Example `0xffffffd8` | `0x06371ea4` | Same nonzero route | `0xffffffd8`, signed32 -40 |
| Example `0xffffffea` | `0x06371eb6` | Same nonzero route | `0xffffffea`, signed32 -22 |

The last two are arithmetic compositions with previously established initializer failure values, not fresh native runs. The outer addition `0xf9c8e134` cancels `0x06371ecc` modulo 2^32. The [conditional return report](lskd_context_return_report.md) supplies the intervening re-encoding, cached RW release, record store and D=0 outer reload premises. A nonzero initializer result is not replaced with the unsupported-operation result `0xffff5966`. [PF3,PF6-PF7]

The initializer tests bit0 of readiness byte `0xfffffe000ccceb00`. Its ready-bit arm sets status zero without reading CCC7848. Consequently, that test alone supplies no cached-pointer validation. The SAT control admits a ready-bit/non-null-invariant mismatch in the abstract source state; it does not establish that native construction reaches such a state. The cold provider, allocation, preparation, publication and cleanup paths remain covered by the earlier [cold-init](kext_cold_init_report.md) and [buffer](kext_buffer_report.md) reports. [PF1,PF6,PF8]

## Original inputs, cached-cell identity and count branching

After zero preflight, source `a52a994..a52a9d4` decodes outer record `+8` with the saved entry key. This recovers low32 of original X4 and stores its zero-extended value at body SP`+0xc8`. Source `a52a9d8..a52a9e0` copies outer record `+0x28`, exactly original X2, to SP`+0x1e8`. The earlier use of SP`+0x1e8` for reader-control state is a different source phase; the offset must not retain that earlier meaning after this overwrite. [PF2-PF4]

The next pool bank selects an original pointer to `0xfffffe000ccc784c`. Source subtracts four and saves `0xfffffe000ccc7848` at SP`+0xf0`. This is the **address of the cached-pointer cell**, not a load of the cached pointer. The initializer's original store at `0xfffffe000a508178` publishes its getter result through that exact cell. This source identity connects initialization and operation staging; it does not establish native backing, capacity, pointer validity or ownership. [PF1-PF6,PF8]

| Original W1 | Post-preflight route | Next retained meaning |
| ---: | --- | --- |
| 1 | `659 -> a520554 -> 2f6 -> a535ad8` | Compare unsigned low32(original X4) with 32; both arms continue |
| 2 | `659 -> a520554 -> 302 -> a534758` | Further operation body remains open |
| 4 | `628 -> a536798 -> 928 -> a5238f8` | Save context`+0x144` address at SP`+0x80`, read its current u32 |
| 5 | `628 -> a536798 -> 2f6 -> a535ad8` | Compare unsigned low32(original X4) with 16; both arms continue |

The first partition uses signed original W1, consistent with the admitted positive selectors. The shared count test uses unsigned32 ordering, selects the higher-count arm at equality and sees the source's truncation of original X4. An X4 value above 2^32 therefore cannot be interpreted as an untruncated count here. No allocation or copied-buffer bound follows from this test alone. [PF2-PF4,PF8]

For W1=1 or 5, a count at or above its threshold selects index `0x996` / `0xfffffe000a57f8e8`; a smaller count selects `0x988` / `0xfffffe000a51a934`, both through diversity `0x0ee4`. This certificate retains those destinations as original fixups. The subsequent [byte-span report](lskd_byte_spans_report.md) analyzes both arms and proves their common builder and distinct continuations; the lower-count arm is not a rejection. For W1=4, the state144 word may be the earlier B+1 update or a different preexisting value; this frontier reads arbitrary current state rather than proving it equals one normalized enum. [PF1-PF4,PF8]

## Reproduction, bounded follow-up and quality gates

The extractor's `--verify` recomputes and compares all source evidence. Twenty-eight new solver obligations are UNSAT and one negative control is SAT. Seven instruction-bank cuts enumerate 1,792 low-byte cases with an independent symbolic upper24 input in each cut; the output reduces to the same exact constant index in every case. This is exhaustive over each cut's 32-bit input, conditional on its supplied frame/static roots. The publication audit replays those queries plus 65 prior UNSAT queries and four prior SAT controls from context-return and reader-lineage evidence, independently checks bytes/fixups/bank identities and register/memory access boundaries, preserves the original inputs, and checks the manifest and path scrub. [PF1-PF8]

There are 155 non-bank scalar instruction instances and 19,712 bank-cut instances, totaling 19,867. The retained source comprises 430 distinct instruction rows across 10 nonoverlapping spans. Ten continuation slots, six static pool-load slots and seven bank-selected slots cover 21 distinct original fixup addresses. Extraction/expression complexity is O(N+I+256R) time and space for input/index bytes N, lifted instances I and bank rules R; SMT solver cost is separate. All memory widths are bytes; the subsequent byte-span certificate establishes byte units for the thresholds. The frozen preflight certificate alone does not prove units. Status arithmetic is modular32, controller/pointer arithmetic modular64, and X4 decoding explicitly truncates and zero-extends. No native target or host service is executed.

| Impact | Bounded follow-up | Discriminating evidence |
| --- | --- | --- |
| High | Recover actual meanings of W1=1,2,4,5 | Follow the count/body and state144 continuations into their input/output and provider calls |
| High | Establish X2/X4 roles and extents | Trace actual dereferences, copy counts and serialization; numeric thresholds alone do not name a buffer or establish its size |
| High | Match cached-byte publication, capacity and lifetime | Join CCC7848 dereferences to descriptor construction/cleanup and concurrent users in the same native epoch |
| High | Establish lock/controller serialization | Track the cached RW domain, controller C/B writes and other users across actual calls and teardown |
| Medium | Complete nonzero-result and cursor paths | Prove actual D=0, guards/PAC and release ownership; inspect all initializer failure exits |
| Medium | Join the named outer call to daemon transport | Match actual IOKit/daemon arguments and result consumers without treating internal records as Mach messages |
| Low | Census no-op hook aliases | Compare other callers/slots and their modifiers before assigning a common semantic role |

**QG1**: No normative claim is required. **QG2**: PF1-PF8 state assumptions, dependencies and falsification probes. **QG3**: The increment covers shared calls/records, controller writes, initializer-result routing, original input recovery, cached-cell identity and count branching; full operation and transport completion remain open. **QG4**: Widths, byte extents, modular arithmetic, signed/unsigned ordering, threshold units and algorithm costs are explicit. **QG5**: The no-op, two record phases, zero-preflight/final-result distinction, X4 truncation and cell-address/pointer distinction are explicit. **QG6**: Original code/fixups, supplied C, frozen initializer/ABI evidence and reproducible source certificates provide primary provenance. **QG7**: Impact-ranked questions bound further data-flow, control-flow, external-input and architectural-interface work.

The [operation 1/5 byte-span analysis](lskd_byte_spans_report.md) resolves original X2 as source, X3 as destination and low32(X4) as a byte count. The 32/16-byte tests select short-copy versus full-split routes; shorter counts copy unchanged and reach conditional outer zero under the prior return premises. Full-split routing copies a 16/0-byte prefix and a 0-15-byte suffix before handing an aligned middle span to A5722B8. Sixty-four bounded direction/length cases prove per-pass snapshot copying; whole-operation overlap behavior, native epochs and daemon serialization remain open.

The [middle-span hardware-staging analysis](lskd_hardware_staging_report.md) now follows A5722B8 through a 16-byte P+134 context window, working IV staging, 81920-byte capped copy chunks and `performHWAESOnBuffer`. Its nominal typed provider ABI receives key-data pointer P+184, IV at bodySP+270, numeric operation 1 and the saved total middle count; copy calls instead receive the current chunk count. The loop and conditional outer 0/-22 status paths are certified. Native descriptor bounds, provider effects, whole-operation overlap and daemon request lineage remain open.

The [descriptor-AES admission and scheduling analysis](aes_provider_admission_report.md) establishes the full64 16-byte-aligned provider length guard through 8388608 B, early key-data+24 low31 publication and optional provider-table key remapping. It connects the earlier sample-state control word to the typed provider selector, resolves descriptor physical-address requests and command fields, and distinguishes the immediate threshold from the operation-specific scheduler quantum. Descriptor extent acceptance, full key policy, native class/configuration, hardware completion and daemon linkage remain open.
