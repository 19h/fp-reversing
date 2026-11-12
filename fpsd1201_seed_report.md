# CoreFP1201 token, entropy, MT-compatible seed expansion and time interface

The subsequent [optional-input and signed-record report](fpsd1201_key_routes_report.md) continues four pinned tuple cases through one mixed-state update and two predicate calls, stopping before the unresolved optional-input word read. It separately tests the upstream selector and preparation-object boundary. Complete mixing/output and native initialization remain unresolved.

The source continuation beyond the previously stopped CASAL restores its token before calling `_arc4random`, fills a 624-word global array with the exact MT19937 seed recurrence, then combines time and two additional random values into a separate four-word tuple. The saved C+0x6f0 pointer starts the tuple/time scratch area. Twelve private cases and an independent replay establish these bounded effects. The earlier omitted request1200/status boundary, later key mixing, remaining context bytes, native initialization and daemon/kext pairing remain unresolved.

## Primary evidence and assumption register

The [producer](triage_evidence/recover_fpsd1201_seed.py), [checks](triage_evidence/fpsd1201_seed_checks.json), [independent auditor](triage_evidence/audit_fpsd1201_seed.py), [receipt](triage_evidence/fpsd1201_seed_audit.json), [read-only IDA snapshot](triage_evidence/fpsd1201_seed_ida_readback.json), [primary-reference fingerprints](triage_evidence/fpsd1201_seed_primary_references.json) and [publication verifier](triage_evidence/verify_fpsd1201_seed_publication.py) retain provenance. Logical JSON links resolve to compressed `.json.zst` files.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| SE1 | The pinned original arm64e image, compiler bounds and format12 rows identify the source. | Compare the full original parent, all dependency hashes, every selected pointer row and live IDA identity/hash. |
| SE2 | The restored zero-control frontier has the frozen private prefix models and the prior explicit request1200/status-check gap. Every continuation depends on them. | Refresh the original prefix and compare every restored CPU component and touched initial RAM page. Execute or independently discharge the omitted call, return checks and initializers before claiming native admission. |
| SE3 | CASAL is modeled as one sequential u32 compare/exchange; concurrent ordering and native ownership are unknown. | Exercise original token 0x5d96 and failed comparisons against 0, 0xffffffff and 0xa94ef. Check complete before/after CPU and memory, including unchanged NZCV. |
| SE4 | The entropy interface returns declared u32 scalars. No native entropy API is called. | Preserve the pre-call boundary; use four first-seed values and compare all 624 original source stores against an independent recurrence. Native randomness, distribution and actual return values remain unknown. |
| SE5 | The time interface uses declared 8-byte seconds and 4-byte microseconds effects, or a selected error/no-write effect. | Check all 16 backing bytes, original field loads/stores, signed/full-width seconds, microseconds, status consumption and untouched padding. Native error-buffer content and errno behavior remain unknown. |
| SE6 | Return models preserve registers except declared outputs or the explicit caller-saved clobber variant. | Clobber X1-X17 and NZCV in a duplicate tuple case, check the same tuple and all original effects, and retain complete CPU frames. This finite result is not a general native ABI proof. |
| SE7 | The MT19937 identification is the completed 624-word seed recurrence and its state extent. Full generator/output equivalence is unknown. | Match the authors' reference, lift the exact update/address/loop source, verify all words for eight source executions, and refresh two primary-source fingerprints. Later key mixing, output tempering and full C[9:128] production remain separate work. |

The CoreFP universal SHA-256 is `68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f`; arm64e slice SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. Parent `[0x8e81c8,0x8fcfa0)` is 85464 B, SHA-256 `4e0ebb4383ce0f3d074358e851dd1bdfff67e77d675e0cfa9e73b4a03ff9a94e`. Live IDA agrees with the original file identity and full parent hash; no IDB operation mutates it.

## Restored boundary and source sequence [SE1-SE3]

The [preceding predicate report](fpsd1201_predicates_report.md) stopped its zero-control case before 0x8ea868. Each producer case refreshes the frozen prefix, compares its full result, restores that receipt-pinned frontier's touched RAM and full CPU, then executes the new bounded suffix. The original prefix contains 19717 source visits plus six modeled steps per refresh. Its explicit gap over `[0x8ea14c,0x8ea164)` still omits request1200 and both return-status checks.

At 0x8ea868 the source instruction is `CASAL W8,W11,[X12]`; X12=image+0x1d33108, comparison W8=0x5d96 and replacement W11=0xa94ef. The original file's four bytes at that cell are `96 5d 00 00`. The sequential model returns the old word in W8 and writes the replacement only on equality. All other CPU components, including NZCV, remain unchanged by this modeled instruction. Three failed-comparison controls stop immediately at 0x8ea86c, before any retry behavior.

The selected successful route source-stores 0x5d96 back to that same cell at 0x8eb7a8, before its first entropy call. This establishes token restoration on this route. It does not establish that the token protects the subsequent global state fill or identify a native lock. The earlier abstract rwlock model in the frozen lookup prefix is a distinct premise; its complete native owner/unlock lifetime remains unknown.

```text
receipt-pinned before CASAL 0x8ea868
              |
    declared sequential compare/exchange
        /                           \
  comparison fails               comparison succeeds
        |                           |
 stop 0x8ea86c              source token restore 0x8eb7a8
                                    |
                           _arc4random at 0x8eb800
                                    |
                         624-word global seed expansion
                                    |
                         _gettimeofday at 0x8eb8e0
                                    |
                    two more _arc4random calls; tuple stores
                                    |
                       stop before 0x8eb9b4 key-mix preparation
```

## Entropy and complete seed expansion [SE1,SE4,SE7]

| Source interface / effect | Original location | Selected slot | IA diversity | Scope |
| --- | --- | --- | --- | --- |
| First `_arc4random` call | 0x8eb800 | 0x1d03df8 | 0xca9b | Source consumes W0 as the initial seed |
| Seed word zero store | 0x8eb804 | Global base 0x1d4551c | n/a | One u32 scalar store |
| Recurrence body | 0x8eb824..0x8eb858 | Loop indices 0x971b / 0x9717 | 0x2af2 | Exactly 623 further u32 stores |
| `_gettimeofday` call | 0x8eb8e0 | 0x1d03c40 | 0x8461 | First case frontier after complete expansion |
| Second `_arc4random` call | 0x8eb94c | 0x1d03df8 | 0xca9b | Later tuple word at +0x0c |
| Third `_arc4random` call | 0x8eb9a4 | 0x1d03df8 | 0xca9b | Later tuple word at +0 |

All offsets use preferred image base zero. Normalized import markers and IA transfers are private models; original import records identify libSystem, not native implementations or native port objects.

With u32 arithmetic modulo 2^32, the source-defined array is:

```text
S[0] = first_entropy_u32
S[i] = 1812433253 * (S[i-1] XOR (S[i-1] >> 30)) + i
       for i = 1..623
```

The state occupies `[image+0x1d4551c,image+0x1d45edc)`, exactly 624*4=2496 B. Original `EOR`/`MADD` implement the update, `ADD ... LSL #2` selects the word address, and the source loop tests the old index against 623. The first loop entry has index 1 and multiplier 0x6c078965; the completion checkpoint has index 624. The final word begins at 0x1d45ed8.

This recurrence, shift, multiplier and word count match `init_genrand` in Nishimura and Matsumoto's [MT19937 reference implementation](https://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/MT2002/CODES/mt19937ar.c), the [2002 initialization revision](https://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/MT2002/emt19937ar.html). The target supplies an external seed here. That completed seed-phase match does not identify the complete surrounding generator or its use as a native cryptographic facility.

Four seed-boundary cases use 0, 1, 0x12345678 and 0xffffffff and stop before the time API. Four tuple cases independently repeat the complete expansion. Each execution checks the original first store and all 623 subsequent addresses, widths and values against a separately implemented integer oracle, totaling 4992 checked words. Four retained algebra obligations and five independent source obligations cover modular update, address scaling, loop partition, time truncation and scratch disjointness. The update/address/branch instructions are compared directly to the original bytes.

## Time and four-word seed tuple [SE1,SE5,SE6]

The constructor's saved C+0x6f0 view is reloaded at 0x8ea638 and saved as the tuple/scratch pointer T at SP+0x498 and SP+0x560. In these retained frames T=C+0x6f0=SP+0x1a30=`0x7a037bc0`. The API receives X0=T+0x10, X1=0. Original source reads an eight-byte field at T+0x10 and a four-byte field at T+0x18 after the call. These correspond to the seconds/microseconds fields in Apple's [timeval definition](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/_types/_timeval.h) and [gettimeofday interface](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/gettimeofday.2.html). The model writes exactly those 12 bytes on selected success and preserves the four following padding bytes. One us is 10^-6 s; modeled seconds/usec patterns are diagnostic inputs, not observed native timestamps.

| Offset from T | Width | Original producer / meaning in this suffix |
| --- | --- | --- |
| +0x00 | 4 B | Third `_arc4random` scalar, store 0x8eb9b0 |
| +0x04 | 4 B | tv_usec, load 0x8eb8f0 and store 0x8eb8f4 |
| +0x08 | 4 B | low32(tv_sec), load 0x8eb8e4 and store 0x8eb8ec |
| +0x0c | 4 B | Second `_arc4random` scalar, store 0x8eb950 |
| +0x10 | 8 B | Modeled timeval tv_sec backing |
| +0x18 | 4 B | Modeled timeval tv_usec backing |
| +0x1c | 4 B | Untouched diagnostic padding |

Thus the first 16 bytes are the source-built tuple `[random3, usec, low32(seconds), random2]`, separate from the first scalar that seeds the global 624-word array. The next 16 bytes back the time structure. The original source consumes only the low 32 seconds bits for the tuple even when the time field contains a full signed 64-bit pattern. Cases use a high-bit seconds pattern, seconds -1 and two subsecond values to distinguish the widths.

The source instructions from 0x8eb8e4 through the next entropy call do not read X0/W0, the time return value. The selected `0xffffffff` return/no-write control still copies the existing time storage into the tuple; that storage is zero in this private fixture. This establishes the bounded status/data-flow behavior, not native failure-buffer content, errno handling or a native failure finding.

The duplicate `clock_A_clobber` case overwrites X1-X17 and NZCV at each modeled external return while preserving the configured X0 result. Its complete tuple is identical to `clock_A`; all source visits, reads, writes and CPU checkpoints independently replay. This tests the selected tuple against the ordinary return model's preservation premise. It does not cover every caller-clobbered register, all possible native side effects or a complete ABI.

The tuple cases stop before 0x8eb9b4. Subsequent optional-key selection, array mixing and generator output are not executed in the delivered profiles. The original C[0:128] still contains only the nine previously defined prefix bytes plus 119 diagnostic zero bytes. No later writer of the global pointer/control needed by the nonzero route is established here.

## IDA and cross-layer evidence boundary [SE1,SE2,SE7]

The retained live IDA snapshot confirms the original universal hash and full parent hash. Eight bounded indexed-xref queries concern selected global state/pool objects and their original pointer-table cells. The subsequent [optional-input report](fpsd1201_key_routes_report.md) identifies the actual selector byte as image+0x1d44409 and distinguishes it from image+0x1d47fb0. The reported references connect the four global objects to their data-table slots; no code xref to those slots is indexed in that snapshot. Computed references and actual writers remain possible. This result is not a writer census or proof of absence. No function, type, name, byte or analysis flag is edited.

The new suffix contains the entropy/time imports above and no imported Mach operation. It adds no native incoming/outgoing port, right transfer or Mach emission site. The earlier source-declared cached name, request1200 gap, later request1201 builder boundary and native daemon/kext pairing retain their previous evidence limits. The new global seed state and scratch tuple are local data-flow facts, not an observed transported payload or native object-ownership contract.

## Validation and bounded continuation

The producer refreshes the frozen prefix for every case. The independent auditor refreshes it once, validates all receipt-pinned restorations, and uses a separate sparse-RAM engine for all twelve suffixes. It checks 70836 original visits, 5232 reads, 5051 writes, 5035 IA/PAC models, 32 explicit sequential/external models, 16 seed checkpoints and 573440 B of initial/final RAM each. Eight complete expansions check 4992 oracle words. Four retained plus five independent source obligations pass as UNSAT; 21 exact original instructions and the complete 85464 B parent are checked. Two primary-source bodies are independently fetched and fingerprinted; only metadata/facts are retained. Fresh IDA identity/xrefs are recorded separately from file/replay evidence. No native target, API, IPC or IDB mutation occurs.

| Impact | Bounded continuation | Remaining premise / falsification probe |
| --- | --- | --- |
| High | Recover the optional-key route, subsequent array mixing and complete output generation. | A matching seed recurrence alone does not identify the whole algorithm, pool buffer or C[9:128] producer. Compare all subsequent source-defined state/output bytes against an independent oracle. |
| High | Establish the actual writers and initialization of 0x1d45f60, 0x1d45f6c, 0x1d44440 and 0x1d47fb0. | The indexed-xref snapshot and frozen warm-state models do not establish a native provider or readiness state. |
| High | Discharge the request1200 call/status checks and join the context path to later helper/request1201 serialization. | Restored private frames do not prove native reply success, complete same-epoch preservation or matched daemon/kext exchange. |
| Medium | Recover the token and earlier rwlock's complete lifecycle and interaction. | The source token reset precedes the state fill; sequential models do not prove native concurrency, ownership or ordering. |
| Medium | Extend external-call/error propagation through later consumers of the seed tuple. | This suffix ignores the time return status, but native error-buffer contents and later handling remain unknown. |
| Low | Classify other callers using the same 624-word state and scratch layout. | Check image identity, record/frame epochs and coefficients before transferring the local contract. |

Quality gates: **QG1** factual technical analysis requires no normative content. **QG2** SE1-SE7 define dependencies and falsification probes. **QG3** this increment covers source token effects, environmental entropy/time interfaces, complete seed expansion, scratch/tuple data flow, selected error behavior and bounded IDA provenance. **QG4** B denotes bytes; u32/u64 widths, half-open extents, s/us units, recurrence bounds, truncation and complexity are explicit. **QG5** prefix/gap/native state, token/rwlock, source-defined/diagnostic bytes, seed/full-generator identity and return/data channels remain distinct. **QG6** pinned original bytes, full state comparisons, independent source/oracle checks, primary fingerprints and read-only IDA evidence support the claims. **QG7** the continuation table bounds and ranks the remaining opportunities. The full investigation remains active.
