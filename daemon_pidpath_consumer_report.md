# Audit PID, process-path buffer and signed result consumer

Further analysis: The [network identity report](daemon_network_identity_report.md) continues all eight positive contexts without adding roots; each stops at 0x1005a8cd4 before reading undefined S+0x858. Separate source entries recover the network identity cache and MAC-property helper, with exact IOKit name-output sites. The initializer-to-caller epoch and native process-path-to-network join remain unknown.

The pending BSM call in the [audit-scratch report](daemon_audit_scratch_report.md) leads to a process-path query. Two explicit nonnull component contexts, continued under declared void BSM returns, execute an exact 1,024-byte zero-fill and stop before an undefined phase word at S+`0x9d0`. Separate phase/bank/PID premises admit `proc_pidpath(pid, R+32, 1024)` at `0x100693890`. Its original return consumer compares the signed 32-bit return with 1 through a recovered address-keyed record. Nonpositive return fixtures restore the 1,056 B cursor reservation and reach `0x100709868`; positive fixtures reach a distinct continuation. [PC1-PC5]

The prior 84 notification-failure contexts remain stopped before the undefined scratch cursor, unchanged. The new contexts use the prior report's separate cursor/token premises. No provider gap, native token origin, cursor bounds, process-path bytes or daemon-kext transaction is established. [PC2-PC4]

```text
Separate nonnull audit component -> pending BSM call
  declared void return, PID-output fixture
  -> original byte-zero loop: [R+32, R+1056)
  -> S+0x9b8 reused as u64 integer 8
  -> STOP before undefined phase read at 0x1008310f8

Separate phase=0x6cf4, bank roots and PID premises
  -> read PID32 at S+0x571c
  -> STOP at 0x100693890: proc_pidpath(PID, R+32, 1024)

Separate int-return fixture; output memory effects unmodeled
  -> address-keyed comparison record and helper 0x100412e1c
  -> s32(return) < 1
       true:  index 0x16ff -> cursor -= 1056; W28=0x74c29dee
               -> STOP at 0x100709868
       false: index 0x16fc -> STOP at 0x1007d04d4
```

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PC-A1 | The pinned original thin daemon and unchanged parent evidence identify the source. Every address claim depends on that identity. | Rehash original bytes, scripts and parent receipts; independently decode the original format-12 pointer words. Native build/provider/task identity remains unknown. |
| PC-A2 | Nonnull component inputs and the void BSM return/PID output are explicit premises. Source continuations depend on their private state. | Replay two placements and source alignments 0/7; verify every return register/flag, output cell, private read/write and source edge. No actual BSM implementation executes. |
| PC-A3 | The phase=`0x6cf4`, two bank roots and alternate PID values are separate continuation premises. PID-call controls depend on these additions. | Require exact equality of all other reconstructed defined bytes and boundary registers/flags; keep the earlier eight phase bytes undefined until the declared cut. |
| PC-A4 | Record and scratch cells have stable SP, modular u32/u64 addressing and disjoint readable backing in finite controls. Full result classification assumes SP aligned to 16 B. | Prove exact key agreement iff SP is even, caller-key parity, all 32-bit return values and arbitrary upper X0 bits. Do not extend native bounds, ownership or alignment from these fixtures. |
| PC-A5 | Logical authenticated edges use exact original target/modifier pairs. Saved-continuation claims require their source or declared-cut provenance. | Verify source stores/loads for both saved continuations, all original pointer words and every replayed edge; reject diversity-only matching. Hardware PAC is not executed. |
| PC-A6 | Path-return values are separate int ABI fixtures, without modeled path-output memory writes. Return-consumer claims depend on this boundary. | Cover zero, positive bounds, INT32_MIN and negative bit patterns; preserve arbitrary upper X0 bits, clobber caller-saved registers/flags, and compare all preserved state. Path strings and native success remain unknown. |
| PC-A7 | Current arm64e SDK declarations identify the process-path call shape. API nomenclature depends on this comparison and the original import. | Compile exact pointer, int and PID widths, prototype and capacity argument to assembly; retain header hashes. Historical SDK/runtime implementation identity remains unknown. |
| PC-A8 | Only the owned increment is published. Preservation/publication claims depend on the exact delta. | Verify source/receipt pins, original inputs, manifest entries, archive round trips and raw/typed/decoded-payload path hygiene. |

## Exact scratch initialization and stack-cell reuse

The BSM continuation starts at `0x100810244` by replacing X0 with saved X19=R+32. The imported void return's arbitrary X0 value is unused. Index `0x1cfe` selects setup `0x10066565c`, which saves continuation `0x10069381c` at S+`0x9110` and fixes the following loop constants. [PC2-PC4]

| Register | Value | Role in the recovered slice |
| --- | --- | --- |
| X0 | R+`0x20` | First byte to zero |
| W9 | `0x773d` | Iteration dispatch index |
| X8 | `0xc4541cbc` | Biased loop limit after entry decoding |
| X15 | `0xc45418bc` | Bias comparison constant |
| X1 | `0xc45418bd` | Biased increment comparison |
| X2 | `0xffffffff3babe743` | Negated increment constant, modulo 2^64 |
| W16 | `0x1bc9` | Phase normalization XOR |
| W3 | `0xffff9374` | Exit-selector additive constant |

At iteration i, `0x100761650` writes one zero byte to X0+i and sets the next offset to i+1. For every u64 i in [0,1023], the original selector chooses index `0x773d` except at i=1023, where it chooses `0x7755`. Each original execution therefore performs exactly 1,024 ordered stores at R+32 through R+1055, without touching the copied token at R through R+31. This initializes the remaining part of the 1,056 B reservation; it is not an allocation or native arena-bounds proof. [PC2-PC4]

The exit normalizes W11=`0x6cf4`, selects `0x1008310e4` and reloads the saved PID continuation. The reset stores the u64 integer 8 into S+`0x9b8` at `0x1008310ec`, replacing that cell's earlier saved-token-pointer role. Execution stops at `0x1008310f8` before reading eight undefined bytes from S+`0x9d0`. No PID-cell access occurs anywhere in the fill interval. Alternate PID-output fixtures leave the recorded fill registers, flags, effects and boundary unchanged. [PC2-PC4]

## PID and process-path call

With the additional phase/bank premises, the reset writes phase-derived state cells and branches through saved X20 to `0x10069381c`. The four-byte load at `0x100693820` reads S+`0x571c` into W0, preserving all 32 PID bits. The local source applies no PID-zero, sign or range filter before the path import. That observation does not establish how the native token/PID was obtained or whether the imported implementation accepts the PID. [PC2-PC4]

For all selector bytes x, the original bank identity `x XOR right[left[x] XOR 0x56] == 0x14` fixes index `0xcccf+0x14`=`0xcce3`. The source proof covers arbitrary u32 controller values and both bank addresses; the original slot names `libSystem/_proc_pidpath`. [PC2-PC4]

| Parameter / boundary | Machine location | Established value |
| --- | --- | --- |
| PID | W0 | u32 value loaded from S+`0x571c`; interpreted as signed `int` by the compared SDK |
| Output buffer | X1 | R+`0x20` |
| Capacity | W2 | 1,024 B |
| Pending call | `0x100693890` | Slot `0x1010a0608`, IA diversity `0x4469` |
| Return | W0 | Signed 32-bit `int` under the compared SDK; native value unknown |

The current SDK prototype and generated arm64e assembly confirm the three arguments and 1,024-byte capacity. No process-path API executes. Native output contents, string termination, errno and API-internal transport remain unknown. [PC4-PC5]

## Address-keyed signed return comparison

At `0x100693894`, the caller saves X0 and sign-extends W0 for the record's value. Arbitrary upper X0 bits do not affect the comparison. Let C=`u64(S+0x10cb8)`, K be the caller's u64 address-derived key and k its low32 bits. The caller writes the following cells before calling helper `0x100412e1c` at `0x1006939a0`. [PC2-PC4]

| Offset from C | Width | Original value |
| --- | --- | --- |
| `0x00` | 4 B | `u32(0x741bcfad-k)` |
| `0x04` | 4 B | Untouched gap; not read by this helper |
| `0x08` | 8 B | `sign_extend_64(return32) XOR K` |
| `0x10` | 4 B | Initially undefined; helper writes the selected index here |
| `0x14` | 4 B | `0x54b7f654 XOR k`; not read by this helper |
| `0x18` | 8 B | `u64(1-K)` |
| `0x20` | 4 B | `k OR 1` |
| `0x24` | 4 B | `0x741bd951 XOR k` |
| `0x28` | 4 B | `u32(0x741bcfae-k)` |

The accessed record spans 44 B. Caller stores define 36 B; the helper's four-byte result defines another 4 B, leaving the gap at +4 untouched. This is an accessed-width contract, not a recovered allocation size or a fully initialized structure. [PC2-PC4]

The helper's normalized key is `u64((C XOR 0x0179fa0fe732d262)*0xba209ef7)`. Exact source proofs establish caller/helper key agreement iff SP is even, and that the caller key is always even. The actual finite SP values are 16 B aligned. Under the stated alignment premise, the helper decodes the signed return and threshold 1, selects the alternate cell at C+`0x28` iff the return is below 1, and writes the following complete u32 result. The proof composes the checked key identity/parity and record-layout lemmas with an arbitrary even common key; it does not assume agreement for odd SP. [PC2-PC4]

| Return class | Helper result / table index | Original target | Subsequent established behavior |
| --- | --- | --- | --- |
| `s32(return32) < 1` | `0x16ff` | `0x1005f2acc` | Zero restoration addend, cursor subtraction `0x420`, W28=`0x74c29dee`, then `0x100709868` |
| `s32(return32) >= 1` | `0x16fc` | `0x1007d04d4` | Distinct continuation; this increment stops before its body |

The original caller loads the helper result with LDRSW, indexes the dispatch table and branches with IA diversity `0x705c`. The two indices are positive and fit the signed extension. Failure-marker naming and positive-path string consumption remain unknown. The result fixtures model no API-output memory writes, including for positive returns; they establish control equations, not recovered native path data. [PC2-PC4]

## Original interfaces and emission accounting

| Role | Index | Original slot | Target | IA diversity |
| --- | --- | --- | --- | --- |
| Fill setup | `0x1cfe` | `0x1010486e0` | `0x10066565c` | `0xd770` |
| Saved PID continuation | `0x86a` | `0x10103e240` | `0x10069381c` | `0x44f6` |
| Fill entry | `0x51b3` | `0x101062c88` | `0x10075f198` | `0x7c16` |
| Fill iteration | `0x773d` | `0x1010758d8` | `0x100761644` | `0x5f6a` |
| Fill exit | `0x7755` | `0x101075998` | `0x10067018c` | `0x5f6a` |
| Phase reset | `0x3fe4` | `0x101059e10` | `0x1008310e4` | `0x1a74` |
| Process-path import | `0xcce3` | `0x1010a0608` | `libSystem/_proc_pidpath` | `0x4469` |
| Comparison helper | `0xced6` | `0x1010a15a0` | `0x100412e1c` | `0x79ec` |
| Nonpositive-result route | `0x16ff` | `0x1010456e8` | `0x1005f2acc` | `0x705c` |
| Positive-result route | `0x16fc` | `0x1010456d0` | `0x1007d04d4` | `0x705c` |

Seventeen original pointer words cover these and reused parent edges. The source slices establish BSM output consumption, local zeroing/comparison and a process-path API call boundary. They contain no Mach send/receive, IOKit call or port-right operation. No incoming/outgoing port identity, disposition or message-emission location is added. Imported implementations and their internal transport remain unexecuted and unclassified. [PC2-PC5]

## Provenance and verification

| ID | Primary evidence and role |
| --- | --- |
| PC1 | Original thin daemon SHA256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; preferred virtual addresses throughout. |
| PC2 | [Extractor](triage_evidence/recover_daemon_pidpath_consumer.py) and [checks](triage_evidence/daemon_pidpath_consumer_checks.json.zst): original source, exhaustive bank identities, seventeen original fixups, twelve nonvacuous source queries and strict source journals. |
| PC3 | Unchanged [parent checks](triage_evidence/daemon_audit_scratch_checks.json.zst) and [audit](triage_evidence/daemon_audit_scratch_audit.json.zst), preserving the separate component assumptions and original retained cursor stop. |
| PC4 | [Independent auditor](triage_evidence/audit_daemon_pidpath_consumer.py) and [audit](triage_evidence/daemon_pidpath_consumer_audit.json.zst): source-byte/register/flag/effect replay, exact cut-state joins, alternate PID controls and compile-only ABI checks. |
| PC5 | Current Darwin SDK `libproc.h`, `sys/proc_info.h` and generated arm64e assembly, with exact source, assembly and relative-header hashes in PC4. Historical SDK/runtime implementation pairing remains unknown. |
| PC6 | [Publication verifier](triage_evidence/verify_daemon_pidpath_consumer_publication.py): exact owned delta, logical manifest, original-input preservation, source/receipt pins, archive round trips and raw/typed/decoded-payload path hygiene. |

Two original component prefixes/fills, sixteen PID controls and sixteen return controls yield 36 intervals, 48,809 source visits, 4,710 reads, 2,464 writes and 2,152 logical edges. Each placement covers eight PID bit patterns and eight return patterns. The latter include zero, 1, 1,023, 1,024, INT32_MAX, INT32_MIN, -1 and -2. These are API-result premises, not claims about possible native success sizes. [PC2-PC4]

Forty independent lifts include four complete fill replays with alternate PID outputs. They check 139,181 source visits, 4,455,072 register values including SP, 139,221 NZCV values, 102,168 read bytes, 8,024 write bytes and 6,246 authenticated edges against original words. Twelve source queries are UNSAT, both 256-input bank identities pass, and the current SDK compile succeeds. [PC2-PC5]

The fixed 1,024-byte fill uses O(1) bounded work and one-byte writes here; parameterized to N iterations its traversal is O(N) time and O(1) extra working state. The comparison helper uses O(1) fixed-width work. Extraction/auditing use O(C*(I+E)+S+Q) time/space in case visits I, recorded effects E, source bytes S and query count Q; solver resources are separate, with a 30 s/query limit. Large JSON is archived with zstd level 22 and exact decompression checks. [PC2, PC4, PC6]

## Bounded continuation

| Impact | Open question | Evidence required |
| --- | --- | --- |
| High | Native token/PID and process identity | Same-build request/trailer provenance, saved X26 lifetime and ordered BSM/process-path observations; local token copying and a PID fixture do not establish a native caller identity. |
| High | Original cursor and phase producers | Matching SP epoch, reaching definitions and all intervening overlapping writes for S+`0x16d0` and S+`0x9d0`; retain the original stops until those joins exist. |
| High | Positive path-buffer consumer | Continue `0x1007d04d4` through pointer/status publication, path-byte reads and complete cursor lifecycle, with declared API-output extents and termination separated from observed data. |
| High | Daemon-kext transaction join | Matching task/connection/provider, selector, buffers, ordered returns and request identity across the native boundary. |
| Medium | Reusable comparison-helper contract | Generalize source-defined threshold/mode/record-key domains before applying this caller-bound signed predicate to other call sites. Odd SP falsifies unconditional key agreement. |
| Medium | Stack-field role epochs | Track the pointer-to-integer reuse at S+`0x9b8` through subsequent reset paths; numeric stack offsets alone do not define permanent field identities. |
| Low | Failure-marker interpretation | Find additional producers/consumers of `0x74c29dee` before assigning a named error or policy outcome. |

## Scoped quality gates

**QG1** passes for factual source analysis. **QG2** passes with PC-A1..PC-A8. **QG3** passes for this increment's source roles, ABI, local data/control flow, environmental interfaces and emission accounting; the full goal remains active.

**QG4** passes with exact byte extents, signed/unsigned widths, modular arithmetic and explicit complexity. **QG5** passes within scope: phase/cursor stops remain explicit, address-key agreement is qualified, the record gap remains untouched, and no API-output contents are inferred from positive return fixtures. **QG6** passes with original source/fixups, twelve checked equations, independent CPU/effect replay and current SDK declarations. **QG7** passes with the impact-ranked continuation table. No native API, IPC, allocation/free, hardware PAC or IDB mutation executes. [PC1-PC6]
