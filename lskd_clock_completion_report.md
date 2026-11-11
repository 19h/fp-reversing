# SecureTime clock fields, explicit unlock and original RTC provider

The start continuation after the clock query writes four more SecureTime fields, prepares an explicit-pointer RW unlock record and returns raw success `0x5e561849` through receiver `+0x38`. It does not test the incoming sysctl status or reload the returned length before these writes. Under the previously published flag, seed and stable-object premises, the clock-bearing field is an exact XOR of a masked seed qword, a fixed constant and the zero-extended four-byte output. Native sysctl success, object validity and lock balance remain **unknown**. [CC1-CC5]

The matching kernel collection identifies a conditional registration of `kern.monotonicclock` by AppleSPMIPMU. Its original OID points to `_sysctlSecondsHandler`, whose nominal method chain serializes bits 46:15 of a 64-bit tick result as four bytes. The provider's separate microsecond interface has a checked integer scaling by 1,000,000/32,768. This establishes the provider's seconds/microseconds source interface; physical calibration, epoch and native registration are unobserved. [CC6-CC8]

[Source and checked queries](triage_evidence/lskd_clock_completion_checks.json.zst), the [extractor](triage_evidence/recover_lskd_clock_completion.py) and the [publication audit](triage_evidence/verify_lskd_clock_completion_publication.py) retain two FairPlay spans / 87 instructions / 348 B and five complete provider compiler bodies / 841 instructions / 3,364 B. Twenty-five operand anchors, one exhaustive 256-input bank, the authenticated return slot, two nominal vtable slots, three original OIDs and eleven installed-SDK assertions pass. Seventeen UNSAT certificates cover 79 source-lifted instruction instances. Complete body capture is distinct from complete semantic lifting. No target, hardware, sysctl, entropy, allocator, synchronization or IDA execution occurred.

```text
FairPlay start: published SecureTime P; constructed/acquired P+18 RW
  -> kernel_sysctlbyname("kern.monotonicclock", output, length=4, NULL, 0)
       [if this source-registered provider is selected]
       kern OID -> AppleSPMIPMU seconds handler
         -> nominal readRTCUpcount -> nominal _readRTCUpcountTicks
         -> ticks >> 15 -> low32 -> request output callback, length=4
  -> source output reload, without a sysctl-status/returned-length gate
  -> fields P+30, P+38, P+10, P+20
  -> explicit unlock record from freshly loaded P+18
  -> raw-success word -> receiver+38 -> frame return
```

Diagram offsets are hexadecimal. The provider selection, object/publication identity and native ownership joins are conditional; the diagram does not assert an observed end-to-end transaction.

## Source identity and incoming contract

Original KC SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Normalized FairPlay image SHA-256 is `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Every new FairPlay instruction and byte bank is compared with the original KC. Provider code and metadata are read directly from its separate KC fileset entry, UUID `6d1fa8d1-80ad-3c2e-b915-30759f729814`; they are not compared against the FairPlay image. Exact symbols, compiler starts and original chained-format-8 pointers establish the provider bindings. Hardware authentication is unexercised. [CC1]

The supplied C retains the caller's `kern.monotonicclock` preparation at lines 20816-20932, recorded in the [preceding evidence](triage_evidence/lskd_secure_time_checks.json.zst). It does not provide a separate `A51C0E0` routine entry. Original instructions at `0xfffffe000a51c0e0..0xfffffe000a51c208` resolve that continuation. No IDA lookup was necessary; the original three reference inputs remain unchanged.

The preceding source sets X19=`0x46ec7c7424bcc931`, W22=`0xea5ebdeb`, W24=`0xa7d93298` and W2=`0xeb78d3a0`. It reloads the flag/seed-pointer cells through SP`+0x78/+0x80`, the global SecureTime pointer cell through SP`+0x10`, and the output into W15. These predecessor instructions are re-lifted from the pinned preceding artifact. A W15 load zero-extends the clock word into X15. Persistence of those roots through returning calls and the join from the retained thirteen start prefixes remain CC2-CC3.

## Complete local field writer

Let T be the published seed-table pointer, P the freshly reloaded SecureTime pointer and C the four-byte output. Under flag=255, original masks select three qwords:

| Source mask | Selected byte offset | Seed u32 indices |
| --- | --- | --- |
| `0xeb78d3a0` | `0xa0` = 160 B | 40, 41 |
| `0xffffffff8f23b568` | `0x68` = 104 B | 26, 27 |
| `0xa7d93298` | `0x98` = 152 B | 38, 39 |

Define A=`u64[T+0xa0]`, B=`u64[T+0x68]`, D=`u64[T+0x98]`, M=`0x7fffffffffffffff`, and O=`u64[P]` after the preceding random request. The complete 32-instruction field slice reduces to:

```text
u64[P + 0x30] = (A & M) XOR 0x46EC7C7424BCC931 XOR zero_extend_u64(C)
u64[P + 0x38] = 0
u64[P + 0x10] = O XOR ((D XOR B) & M) XOR 0x35659B426B46BEB1
u32[P + 0x20] = 0
```

The source loads O through the self-reference at P`+8`. Joining it to O=`u64[P]` requires that the preceding self-reference store and publication epoch remain valid. All seed qwords and O are otherwise arbitrary symbolic inputs; no entropy value is assumed. Seed index 40 is one of the preceding edited indices 0,4,...,60; the others listed here are outside that write set. This report does not reconstruct their actual values. [CC2-CC4]

The first formula is exact despite the intervening `BFI W11,W10,#1,#3` and add/subtract/AND sequence. The source's fixed constant has zero bits 1..3; replacing those bits from the seed leaves the bits relevant to the subsequent clock AND unchanged. The complete source lift proves the resulting XOR relation for every qword A and every u32 C. No standardized cipher or time-integrity property is inferred.

| Object offset | Width | Source-visible role on this selected initialization path |
| --- | --- | --- |
| `+0` | 8 B | Earlier seed-derived qword; subsequent four-byte random request overlaps its lower half |
| `+8` | 8 B | Earlier self-reference P |
| `+0x10` | 8 B | New folded object/seed relation above |
| `+0x18` | 8 B | Earlier precleared/conditionally constructed RW pointer |
| `+0x20` | 4 B | New zero word |
| `+0x24..+0x2f` | 12 B | Outside the combined explicit source-store coverage |
| `+0x30` | 8 B | New masked-seed/clock XOR relation |
| `+0x38` | 8 B | New zero qword |

The new four stores cover 28 distinct bytes. The preceding explicit stores cover another 24 distinct bytes, giving 52/64 B of visible coverage. This is a store-footprint statement, not proof that the remaining twelve bytes contain uninitialized native data, padding or meaningful fields. Allocator policy and later readers must establish their contents and use. [CC3-CC4]

## Status handling, explicit unlock and source return

A register-use audit finds no read of the incoming X0/W0 sysctl status before `LDR X0,[SP,#0x128]` overwrites it at `0xfffffe000a51c170`. The new consumer has no conditional branch before the unlock call and no explicit reload of SP`+0x1d8`, the caller's returned-length cell. The preceding query block prezeroes its four-byte output and later reloads it. Consequently, the stored clock-bearing word depends on the output bytes, including any unchanged prezeroed bytes, rather than a local status/length admission test. Actual API writes and outer error semantics remain unknown. [CC2-CC5]

At `0xfffffe000a51c164`, the caller freshly loads the embedded RW pointer at P`+0x18`. For reused record R=W`+0xa8`, its stores reduce to:

```text
unlock_key = u32((low32(R) XOR 0xDFB9786F) * 0x1E2776FD)
R.u32[0] = unlock_key + 0x1D3
R.u64[+8] = freshly_loaded_P.u64[+0x18]
```

Call `0xfffffe000a51c1f0` resolves through slot `0xfffffe0008471498` to release adapter `0xfffffe000a551f38`, diversity `0x84cc`. The exhaustive D-bank rule uses key `0xbb` and additive `0x92c`. The [existing release contract](lskd_continuations_report.md) selects the explicit pointer when nonnull; the original kernel binding is `IORWLockUnlock` / `lck_rw_done` at `0xfffffe000bd08174`. Its null-explicit behavior can instead use the cached global. The selected constructor-success/stable-object epoch supplies the embedded pointer. Matching it to the earlier acquired lock still requires CC3 and CC5.

After the adapter returns, index `0x30c` selects `0xfffffe000a52e4b0`, diversity `0x0343`. W8 is explicitly set to raw success `0x5e561849`; the common block stores it at receiver `+0x38`, restores the caller frame and returns. This closes the selected internal start continuation through source return. It does not establish an outer normalized method result, daemon reply, native execution or SecureTime object/free lifetime. The earlier allocation-null and constructor-nonzero source arms also preserve this raw-success word. [CC3-CC5]

## Original OID and registration context

The KC's AppleSPMIPMU entry contains the following original 80 B OID records. Their shared parent pointer decodes to exact `_sysctl__kern_children` at `0xfffffe0007f889e0`. Each has file number -1, a separately authenticated handler pointer and exact name/format/description strings. File `oid_arg1` is zero for the first two; the registration source overwrites it with the driver receiver. [CC1,CC6]

| OID address | Name below `kern` | Kind / format | Original handler |
| --- | --- | --- | --- |
| `0xfffffe000cc6b508` | `monotonicclock` | `0x81400002`, `IU` | `0xfffffe0009e4195c`, `AppleDialogSPMIPMURTC::_sysctlSecondsHandler` |
| `0xfffffe000cc6b558` | `monotonicclock_usecs` | `0x81400004`, `Q` | `0xfffffe0009e419cc`, `AppleDialogSPMIPMURTC::_sysctlMicrosecondsHandler` |
| `0xfffffe000cc6b5b0` | `monotonicclock_rate_usecs` | `0x81400004`, `Q` | `0xfffffe000c2dd5f0`, exact `_sysctl_handle_quad` |

The first two descriptions are `elapsed time`; the rate description is `elapsed time rate`. Installed SDK 27.2, compiled with its selected Apple Clang for `arm64e-apple-macos13.0`, passes eleven size/offset/flag assertions. In that comparison, the first kind is `CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_OID2`; the write flag is absent. Original handler loads/stores independently corroborate the accessed layout. The SDK check does not prove every historical private field or any user-space policy/admission behavior.

The complete 489-instruction `AppleDialogSPMIPMURTC::handleStart` body is captured. The seconds registration sequence at `0xfffffe0009e4165c..0xfffffe0009e41668` supplies the first OID, stores X19 (the driver receiver) at record `+0x18`, and calls stub `0xfffffe0009e44c10`. The microsecond OID follows at `0xfffffe0009e4166c..0xfffffe0009e41678`. Original import slot `0xfffffe000832ec18` binds the stub to exact `_sysctl_register_oid` at `0xfffffe000c2dcf90`.

Registration lies after provider/configuration gates in that startup body, including a nonnull provider result, its flag branch, a virtual initialization-result bit and a later virtual method's zero-status gate. The complete source context is retained; its external results and native traversal are unobserved. The existence of an OID record in the KC therefore does not prove that this OID is currently registered or selected for the FairPlay call. Duplicate registration, other providers, startup failure and later removal remain separate questions. [CC6]

## Seconds projection and lower RTC boundary

The seconds handler uses its argument pointer as the receiver for vptr slot `+0x8d8`. The exact nominal AppleDialogSPMIPMURTC vtable is at `0xfffffe000832d470`, with vptr base at symbol `+16`:

| Vptr offset | Original slot / diversity | Target and role |
| --- | --- | --- |
| `+0x8d8` | `0xfffffe000832dd58`, `0x3a08` | `0xfffffe0009e43610`, exact `readRTCUpcount()` |
| `+0x8e8` | `0xfffffe000832dd68`, `0xbe44` | `0xfffffe0009e43650`, exact `_readRTCUpcountTicks()` |

`readRTCUpcount()` calls the tick method and applies `LSR X0,X0,#15`. The seconds handler stores W0 into a four-byte stack temporary, then invokes `request->oldfunc` from request `+0x28` with X0=request, X1=temporary and W2=4. Its returned status comes from that output callback. Under the matched-vptr, returning-call and request premises, the serialized numeric word is exactly

```text
seconds_word32 = low32(unsigned_ticks64 >> 15)
               = ticks[46:15]
```

This projection is periodic under addition of 2^47 ticks modulo 2^64. The handler's four-byte output discards higher tick bits; it does not serialize the full u64 upcount. This is the provider's seconds interface by its exact handler name and corresponding microsecond scaling. It does not establish a Unix epoch, boot epoch, physical frequency, monotonic native sample sequence or calendar time. [CC6-CC8]

The separate microsecond handler's eight-byte path uses the exact source decomposition

```text
q = unsigned_ticks64 >> 15
r = unsigned_ticks64 & 32767
microseconds_word64 = u64(q * 1000000 + ((r * 1000000) >> 15))
                    = u64(floor(unsigned_ticks64 * 1000000 / 32768))
```

The remainder product is below `32768 * 1000000`, so the original UMULL result fits u64. A source certificate verifies the decomposition and an independent integer quotient/remainder certificate verifies the exact floor identity; the final u64 reduction follows modular congruence. A direct widened-bitvector solve returned `unknown` with a 10 s limit and is excluded from the certificate set. The checked composition establishes the same projection. It does not substitute a finite-sample check.

The captured 215-instruction `_readRTCUpcountTicks()` body reaches further environmental interfaces. Its null auxiliary-context arm uses the provider at driver `+0x110`, the u16 register selector at driver `+0xf2`, an output scratch pointer and length 6 at provider vptr slot `+0x8e0`. Its nonnull auxiliary-context arms use different object/method routes. Those calls and actual register bytes remain unresolved. The body also contains an error-dependent clear of its local tick cell at `0xfffffe0009e4390c`; a serialized zero is therefore insufficient by itself to establish a successful physical read. This report captures those source paths without claiming their complete semantics, policy, hardware status or execution. [CC7-CC8]

## Assumption register

| ID | Assumption and dependent results | Stress test or falsification probe |
| --- | --- | --- |
| CC1 | Pinned original KC, fileset identity and normalized FairPlay image identify this build. All addresses, metadata and imports depend on it. | Rehash, compare selected FairPlay bytes/tables, reparse provider compiler starts, exact symbols and original chained pointers. |
| CC2 | The previously sourced flag=255, seed-pointer and frame-root epochs reach the new continuation through returning calls. The three seed indices and incoming constants depend on this. | Re-lift predecessor instructions, check dependency hashes and retained frame producers, then recover intervening writers and actual native epochs. |
| CC3 | P, its self-reference, frame/record and seed storage have the declared valid, nonaliasing extents; fresh pointer/lock reloads preserve object identity. Field composition and acquire/unlock correspondence depend on this. | Establish allocator backing, inspect all competing publications/aliases and join each reaching store to its load. Keep fixed symbolic cells separate from an unrestricted alias proof. |
| CC4 | Scalar A64 widths, sign-extension, BFI, UMULL and modular arithmetic follow the decoded semantics. Exact field/conversion formulas depend on them. | Reinterpret all selected original operands, prove the complete field writer and scaling decomposition, and separately check integer quotient/remainder identity. |
| CC5 | The earlier release adapter applies to the new source-produced phase/pointer and returns normally. Native balance additionally requires actual prior ownership. | Re-solve its original selector and pointer-gate certificates; match real lock construction/acquisition/release and outer result consumers. |
| CC6 | This conditional OID registration succeeds and its handler/receiver is selected by the named request. End-to-end provider attribution depends on it. | Recover registration/lookup conflicts, removal and startup gates; compare actual OID/arg1/handler epochs. The source record's existence alone is insufficient. |
| CC7 | The actual receiver uses the checked nominal vtable and the tick method returns through the declared ABI. Seconds projection and lower-provider join depend on it. | Verify runtime vptr/overrides, slot authentication and actual returned tick source; fully recover the provider and auxiliary routes. |
| CC8 | Request/callback storage and returning-call preservation satisfy the stated interface; physical units remain an unmeasured interpretation of the paired interfaces. Serialization and any physical-time claim depend on further evidence. | Trace output callback status/extent, sample matched hardware and clock epochs, recover calibration/frequency and account for truncation, zero-result and wrap cases. |

## Bounded continuation

| Impact | Next question | Evidence required |
| --- | --- | --- |
| High | How do SecureTime readers decode and validate the new fields? | Exact consumers of `+0x10/+0x30`, matching seed/self-reference epochs, time admission and later output serialization. |
| High | Which hardware/auxiliary route supplies the tick word? | Complete methods below provider `+0x8e0` or auxiliary `+0x140`, register protocol, error mapping and native configuration. |
| High | Is the nominal OID/provider selected in a real FairPlay request? | Source and native registration, lookup, receiver/vptr and output callback identity; no matching transaction is established here. |
| High | Where are SecureTime P and its RW pointer freed, and how are partial objects admitted? | Complete publication/consumer/free census, concurrent pointer epochs and allocator failure admission. The current source unlock is distinct from destruction. |
| Medium | What happens across output truncation, zero tick results or failed clock reads? | Later field readers, provider status behavior and actual returned-length handling; the start suffix has no local status/length gate. |

## Reproduction and scoped quality gates

Run `recover_lskd_clock_completion.py --verify` with `triage_evidence` on the Python module path, Z3 and the selected Xcode SDK available. It re-extracts original code, OIDs, chains, vtable slots and bindings; re-lifts the selected current/predecessor slices and reruns the installed-SDK comparison. The publication audit re-solves seventeen serialized queries and the three retained original unlock certificates, checks the exact owned manifest delta, preserves the three original inputs and scans raw/decompressed owned content for analyst paths. Substantial JSON is stored as verified Zstandard archives.

For bytes B, instructions I, nlist records N and bank rules R, extraction costs O(B+I+N+256R) time/space plus chained-pointer work; repeated exact-name scans add a constant number of O(N) passes. Local lifting builds O(I) expressions; solver cost is separate, with a 10 s per-query limit. The new FairPlay suffix has constant straight-line work outside its returning helper. Provider latency, hardware retries, native memory overhead and physical clock error bounds remain unknown. Offsets/capacities are bytes, integer arithmetic has explicit u32/u64 widths, and the numerical scaling is exact within those widths.

- **QG1** passes for factual source/interface analysis.
- **QG2** passes with CC1-CC8, dependent claims and falsification probes.
- **QG3** passes for this increment's field formulas, explicit unlock/return, OID registration context and nominal RTC projection. The broad goal remains active.
- **QG4** passes with byte footprints, seed indices, bit projection, modular arithmetic and exact integer scaling; physical calibration is unmeasured.
- **QG5** passes with nonaliasing/storage premises, source status-channel behavior, partial field coverage, nominal/native distinctions and the excluded direct-solver result explicit.
- **QG6** passes with original bytes/starts/chains/symbols, pinned predecessor evidence, installed-SDK comparison and checked source/decomposition certificates.
- **QG7** passes with impact-ranked reader, provider, registration, lifetime and edge-case questions.

The [conditional stored-clock reader report](lskd_clock_reader_report.md) decodes the initialization relation, proves the zero-arm rewrite and recovers an exact unsigned fresh-versus-stored comparison. Fifteen UNSAT queries and two SAT controls qualify its phase/alignment and comparison contracts. Actual reader phase/frame roots, both helper-bank bindings, later admission/result and native daemon-kext lineage remain unknown.

The [elapsed high-water and continuation-record report](lskd_clock_accumulator_report.md) reduces the selected reader to a conditional unsigned elapsed high-water update. Thirty-four UNSAT certificates cover 754 lifted instruction instances; two SAT controls distinguish decoded-accumulator wrap from elapsed nondecrease and expose the missing signed-result range contract. Fresh embedded-pointer release preparation and a 40 B continuation envelope with 36 B locally written are recovered. Actual phase/frame roots, concrete helper targets, final context predicate, native epoch and daemon-kext lineage remain unknown.

The [context-comparison report](lskd_context_compare_report.md) corrects the continuation operand to the carry-flag XOR, recovers the complete comparison-record leaf and conditionally proves the final local gate: decoded accumulator < normalized context value and saved control low byte = 1. Twenty-two UNSAT certificates and two SAT controls cover the corrected handoff and carry-aware predicate. A 256-slot census retains three matching-diversity helper candidates; actual bank roots, saved phase, context/control producers and daemon-kext lineage remain unknown.
