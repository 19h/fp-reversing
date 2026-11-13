# Restored arena-context lock argument and state-path encoding

Follow-up: The [context state-publication report](daemon_context_state_publish_report.md) follows the second allocation into raw C+0x10 publication, decoding, count/data copying, additional context layouts and entropy/clock boundaries. The NULL branch frees the encoded temporary under a declared return and reseals context/reference before an undefined caller-pointer stop.

The original continuation after raw-reference publication passes the restored context word at C+8 to `pthread_rwlock_wrlock` at `0x100361df4`. The word is captured at `0x1005fae24` and retained across the acquisition adapter's separate `pthread_once` call. All forty checked continuations pass the exact captured word: thirty allocated-token controls and ten controls containing the opaque word preserved after first-creator failure. This establishes argument flow; native lock validity, admission of the failed-constructor state and successful synchronization remain unknown. [CLU1-CLU4]

The same continuation constructs `/var/db/fpsd/SC Info\0` at S+0x103a6, scans a distinct initializer-compatible copy at S+0x103db, and reaches `malloc(21)` at `0x1006b6fb0`. Under a separate non-NULL allocation return, original source writes a 21-byte XOR-0x98 representation of the constructed string, then reaches a second `malloc(21)` at `0x1004b457c`. A separate NULL return instead reaches the cleanup adapter's once call. No filesystem operation or IPC emission executes in this increment. [CLU1-CLU5]

```text
raw context C restored, reference published
  -> increment adjacent control32; release fallback lock
  -> construct state string at S+0x103a6
  -> read C+0x18, C+0x10, C+8
  -> capture C+8 -> adapter -> pending once
       + separate once-return premise
  -> pending wrlock(captured word)
       + separate lock-return premise
  -> scan separate initializer-compatible S+0x103db string
  -> pending malloc(21)
       + NULL return premise --------> cleanup -> pending once
       + non-NULL owner premise ----> encode constructed string
                                       -> pending second malloc(21)
```

| Evidence | Primary artifact and scope |
| --- | --- |
| CLU1 | Original thin image SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [extractor](triage_evidence/recover_daemon_context_lock_use.py) retains original source regions, visited instruction words, fixups, register frames and memory effects. |
| CLU2 | Frozen [unseal receipts](triage_evidence/daemon_context_unseal_checks.json.zst), decoded SHA-256 `b4f3b10a7c3b5f57d9a680c1e88a4fb2a9b473af27fb0b353e23fd7ab87048fe`; twenty retained parent boundaries cover thirteen producer profiles and eight caller contexts. |
| CLU3 | [Initializer receipts](triage_evidence/daemon_return_bank_origins_checks.json.zst); twelve complete source-writer ledgers establish two additional bank roots and the distinct 21-byte scan string. Fresh original initializer replay checks their final values. |
| CLU4 | [New checks](triage_evidence/daemon_context_lock_use_checks.json.zst): forty continuations, four separate allocation-return controls, all GP/Q/NZCV frames and explicit root/import/owner premises. |
| CLU5 | [Independent auditor](triage_evidence/audit_daemon_context_lock_use.py) and [audit receipts](triage_evidence/daemon_context_lock_use_audit.json.zst): scalar/AdvSIMD replay, byte/state joins, initializer replay and five nonvacuous UNSAT source obligations. |
| CLU6 | [Publication verifier](triage_evidence/verify_daemon_context_lock_use_publication.py): source/dependency/receipt pins, exact manifest delta, preserved original inputs, compressed archives and raw/typed/decoded path hygiene. |

## Context fields, calls and local records

| Source location | Established operation | Width, extent or argument |
| --- | --- | --- |
| `0x10050feb4` | Increment adjacent control `0x1010c5760` | u32, modulo 2^32; retained value 0 -> 1 |
| `0x10050ff50` -> `0x1004423f8` | Cleanup adapter before context-field use | X0=S+0x10cb8 |
| `0x100442650` | Pending `pthread_once` in cleanup | X0=`0x1010b8cd0`, X1=callback `0x10040ebd4` |
| `0x100208efc` | Pending `pthread_rwlock_unlock` | First cleanup uses fallback address `0x1010b7478` |
| `0x10050ff98` -> `0x1000056c8` | Zero-return leaf after cleanup | Original leaf sets W0=0 |
| `0x10050fff8..0x1005100ec` | Construct encoding-input string at S+0x103a6 | Twenty-one individual byte stores including NUL |
| `0x1006150f4` | Read C+0x18; zero selects C, nonzero selects zero | u32; retained contexts contain zero |
| `0x100615100`, `0x1006053bc` | Read/test C+0x10 on the retained route | u64; retained contexts contain zero; later field semantics unknown |
| `0x1005fadd4` | Read raw context word at C+8 | u64; no dereference or object validation here |
| `0x1005fae20`, `0x1005fae24` | Prepare adapter record at R=S+0x10cb8 | Encoded u32 at R+0 and captured u64 at R+8; intervening four bytes are not defined by these stores |
| `0x1005fae90` -> `0x10043e280` | Invoke acquisition adapter | X0=R; captured word reaches X19 before once |
| `0x10043e508` | Pending acquisition `pthread_once` | Same once token/callback pair as cleanup |
| `0x100361df4` | Pending `pthread_rwlock_wrlock` | X0 equals raw C+8 word in every checked case |
| `0x1005faea0` | Re-read C+0x18 after the declared lock return | u32; retained value zero |
| `0x10052da40` | Scan initializer-compatible string at S+0x103db | Twenty-one one-byte reads through NUL |
| `0x1006b6fb0` | Pending first `malloc` | X0=21 B |
| `0x1006b6fb4` | Save full pointer return | u64 at S+0x7a70; full-width NULL test follows |
| `0x10052e5e8`, `0x10052e608` | Read constructed encoding input; write encoded output | Twenty body bytes, one byte per iteration |
| `0x1004afba8`, `0x1004b4514` | Write encoded terminator twice at output+20 | One byte each, value `0x98` |
| `0x1004b457c` | Pending second `malloc` after encoded output | X0=21 B; second return and output remain unknown |
| `0x1006b26c0` -> `0x1004423f8` | NULL first-allocation branch invokes cleanup | Stops at pending once; native cleanup outcome unknown |

C=`0x6500115b20` is the explicit 552-byte foreign owner restored by the parent. All five context reads per continuation remain inside that owner. This increment writes no context bytes. The allocated output control owns exactly 21 B at private-model address `0x6600003000`; none of its initial bytes is declared defined. The source writes all 21 bytes before the next boundary and never reads the new allocation. Page mapping does not extend the declared owner or define neighboring bytes. [CLU2,CLU4-CLU5]

## Input provenance and representation

| Caller value | Source evidence | Continuation premise |
| --- | --- | --- |
| S+0x968 -> `0x100fc4130` | Initializer u64 writer `0x1004c2534`, one write and no later overlap in each of twelve profiles | Added only after the original unknown-byte stop at `0x1005fae50` |
| S+0x960 -> `0x101031ea0` | Initializer u64 writer `0x1004c2b30`, same twelve-profile coverage | Added after the next original unknown-byte stop at `0x1005fae64` |
| S+0x103db, 21 B | Initializer byte writers `0x10061a7c0..0x10061a908`, exact `/var/db/fpsd/SC Info\0`, no later overlap | Added only at the original first unknown-byte scan stop; initializer and caller frames remain separate epochs |
| S+0x103a6, 21 B | Current continuation byte writers `0x10050fff8..0x1005100ec` construct the same literal | Continuously sourced within this increment; distinct from the separate scan-string premise |

The encoder's twenty body iterations read S+0x103a6+i, i=0..19. Original `0x10052e5c4..0x10052e60c`, with the recorded controller W12=`0xb374`, reduces to `encoded_byte = plain_byte XOR 0x98`. The source lift checks the entire original expression, including the variable-shift instruction and low-byte store. A separate theorem covers every possible input byte. Two explicit stores write encoded NUL=`0x98` at index20; the second repeats the first. Output is `b7eef9eab7fcfab7fee8ebfcb7cbdbb8d1f6fef798`. It is an encoded local representation; the pending second allocation has no established copy/decode consumer here. [CLU4-CLU5]

The parent raw-field coverage requires a correction. Of thirteen producer profiles, eight contain allocator token `0x6600001000`; five first-creator failures preserve opaque word `0xf64ac418c20e70bc` because the destination was not overwritten. The parent's twenty combined cases contain fifteen allocator tokens and five preserved words. This increment repeats those twenty cases with two coupled return/clobber fixtures, producing thirty and ten respectively. There is no NULL raw-field control, and a preserved nonzero word does not establish an initialized lock. The [unseal report](daemon_context_unseal_report.md) now states that distinction; its source receipts and byte-equality results are unchanged. [CLU2,CLU4-CLU5]

Forty continuations cover the parent case set under two joint ABI fixtures: low32 imported status0 versus synthetic35, different unspecified X0 upper32 bits, different NZCV, and different caller-clobbered SIMD contents. These fixtures are not a Cartesian separation of status and clobber effects and do not claim that any native pthread routine returns35. Low64 of Q8..Q15, X18..X29 and SP remain preserved across each declared imported return; upper64 of Q8..Q15 and the other Q registers are clobbered. Every subsequent full Q-register state is replayed. Four additional component controls use the final parent/caller case, two clobber fixtures and NULL/non-NULL malloc returns. They do not extend allocation-return coverage to every constructor profile. [CLU4-CLU5]

## Assumption register

| Assumption | Dependent results | Stress test or falsification probe |
| --- | --- | --- |
| CLU-A1: Pinned image and logical fixups identify this source | All addresses, calls and reductions | Recheck SHA-256, each visited instruction word and every used original fixup; hardware PAC remains unexecuted. |
| CLU-A2: Parent constructor-compatible context/caller transfer applies | Field layout and subsequent selected route | Exact GP/Q/SP/NZCV and byte joins; retain all twenty parent cases and distinguish failed-constructor words. Native admission can refute applicability. |
| CLU-A3: Two initializer-compatible bank roots apply in the separate caller frame | Acquisition-adapter selection | Preserve original unknown masks; check twelve writer ledgers, no overlap and fresh initializer replay. A different live bank/root refutes applicability. |
| CLU-A4: Separate initializer-compatible scan string applies | Scan termination and first allocation size | Preserve unknown first-byte stop; check all21 initializer bytes and final original replay values. Native identity with the constructed string remains unknown. |
| CLU-A5: Declared import returns and ABI preservation admit continuation | Post-once, unlock and wrlock suffixes | Check exact return/memory joins and preserved registers; vary joint status, flags, upper bits and SIMD fixtures. Native import effects and successful exclusion remain unknown. |
| CLU-A6: Non-NULL malloc control supplies a disjoint 21-byte owner | Encoded output and second allocation boundary | Initial allocation bytes remain undefined; check all22 byte stores, exact21 final bytes and absence of allocation reads. Actual native allocation/lifetime remains unknown. |
| CLU-A7: Scalar/AdvSIMD models implement the original operations | Source roles, equality and algebra | Independently replay every register and byte effect; check five nonvacuous source obligations; unsupported operations fail closed. |
| CLU-A8: First subsequent import bounds each allocation control | Later persistence, cleanup, external interfaces | Continue the second malloc return or NULL-path cleanup separately. File operations, release completion, resealing and transport remain unknown. |

Extraction and independent replay use O(receipt bytes + cases*(visits+effects)) time and storage. The path body uses O(n) time and n output bytes for n=21 B, with O(1) source auxiliary state. Fixed source regions and five solver queries are separate; each query has a 30 s limit. The exact byte dimensions are 20 non-NUL bytes +1 terminator =21 B; 20 body stores +2 terminator stores =22 write events to21 unique bytes. [CLU4-CLU6]

## Validation, bounded continuation and quality gates

The source receipts contain 324 intervals, 122,212 original instruction visits, 16,646 read events, 2,404 write events, 3,696 logical edges and 162 internal call records. Independent replay checks 3,921,152 GP/SP values, 3,921,152 full Q-register values, 122,536 NZCV states, 92,612 read bytes and 12,540 written bytes, including 3,536 authenticated-branch origin/modifier checks. All forty context-word captures and wrlock arguments match exactly. The checked continuations perform200 context-field reads and scan840 path bytes. Twelve fresh initializer runs check21,396 source visits,24 new root cells and252 scan-string bytes. [CLU3-CLU6]

Five nonvacuous UNSAT obligations check the arbitrary-u64 capture without validation; arbitrary-u32/u64 context-field selection; the original all-byte XOR encoder under its explicit controller premise; full-u64 malloc-return saving and NULL selection; and the encoded terminator predicate. They complement concrete original-source replay rather than proving native reachability or all API outcomes. The prior unseal receipts remain unchanged; only their inaccurate zero/nonzero coverage description is corrected. [CLU2,CLU5-CLU6]

| Impact | Next evidence | Purpose and present limit |
| --- | --- | --- |
| High | Continue the second allocation return through copy/decode, publication and later consumers | Establish whether the encoded local path becomes context state or reaches a filesystem API; neither is established here. |
| High | Follow constructor-failure admission and raw-field initialization across a continuous caller epoch | Determine whether preserved opaque words can reach this consumer natively. Current source composition transfers separate compatible states. |
| High | Recover unlock/reseal ordering for the context lock and raw-reference cell | Establish when representations and synchronization arguments remain valid across callers. |
| Medium | Replace the separate scan-string and bank-root premises with continuous original caller state | Resolve the matching-literal/different-provenance boundary and eliminate unjoined frame assumptions. |
| Medium | Continue NULL-allocation cleanup through actual release/result handling | Distinguish pending cleanup calls from completed release and externally visible failure. |
| Low | Correlate a later source-established transport call with existing Mach/IOKit contracts | The checked suffix adds no port emission, right transfer or daemon-kext transaction. |

**QG1** passes: factual source/ABI analysis. **QG2** passes: CLU-A1-CLU-A8 register dependencies and falsification probes. **QG3** passes for this bounded increment: raw-field consumers, lock argument, path sources, encoding, allocation branch controls and reporting correction are covered; the full investigation remains active. **QG4** passes: u8/u32/u64 widths, owner extents, byte/event counts and complexity are explicit. **QG5** passes: failed-creator preserved words, absent NULL-field coverage, the two string sources and component gaps remain distinct. **QG6** passes after original-byte, independent replay, initializer, solver, receipt, manifest and publication checks. **QG7** passes: impact-ranked continuation and the present native/transport limits are bounded above.

Decoded checks SHA-256: `ce8d539c6aa4f83cb5130a7f3351fbe30f29c0f5a41b23efeceb33424240e44f`. Decoded audit SHA-256: `99d38ace846d3a593d65caeaf45af8699f6bf8cefa15c369e7160c7a95feb4a4`.
