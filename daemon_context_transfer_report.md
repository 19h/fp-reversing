# Unknown-preserving context transfer and encoded comparison ABI

Current bank-origin increment: The [bank-origin continuation](daemon_return_bank_origins_report.md) verifies an actual later producer/result for this report's 0x10041a5e0 comparison leaf and separately recovers complete signed/unsigned less-than leaf 0x100427514. The shared record storage changes meaning across epochs; IA diversity alone does not identify the callee.

The original callback continues past the SP+`0x5A8` boundary while retaining fourteen unknown u64 inputs as **112 independent symbolic bytes**. Four source contexts reach `arc4random` at `0x100409574` with concrete control targets, addresses and final X registers. Independent A64 replay matches every recorded register/memory effect across sixteen backing patterns/context combinations. Copied unknown bytes remain unknown; they are not zero-initialized to make execution progress.

This also recovers the complete leaf routine at **`0x10041A5E0`**: it decodes two u64 operands and a mode from a 48-byte address-coded record, selects equality or unsigned greater-than, and writes an encoded u32 choice at record+`0x10`. Its caller compares zero with image-global u32 `0x1010C8258`. A fresh-image zero-fill premise supplies zero in the selected executions; the generic caller contract covers every u32 value.

## Provenance and assumptions

Primary image: `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Addresses are preferred virtual addresses. [Contracts](triage_evidence/daemon_context_transfer_contracts.json) retain six explicit spans, two exhaustive byte banks, 40 original fixups, 470 matched current IDA rows, the zero-fill section and the installed SDK declaration. [Symbolic profiles](triage_evidence/daemon_context_transfer_profiles.json) retain compressed byte-level journals and 1,246 original instruction rows. [Independent replays](triage_evidence/daemon_context_transfer_replays.json), [checks](triage_evidence/daemon_context_transfer_checks.json) and [ten source proof pairs](triage_evidence/daemon_context_transfer_proofs.json) retain the verification evidence. The preceding [arena-storage report](daemon_arena_storage_report.md) remains frozen.

| ID | Assumption / boundary | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| CT1 | The pinned source is the intended daemon | PCs, fields and routines | Rehash original opcodes/fixups and compare live IDA bytes; native daemon/kext pairing remains unknown |
| CT2 | The retained arena-storage prefix establishes each selected incoming state | Whole-prefix continuity | Freshly replay all four preceding contexts and compare their complete retained records |
| CT3 | Frame/owner storage is mapped, valid and disjoint from the image | Symbolic byte aliases and concrete replay | Check all addresses/widths and independent interpreter accesses; reject unmapped or unknown-dependent addresses |
| CT4 | The fourteen initial words are independent unknown bytes | Noninterference and field preservation | Introduce 896 symbolic bits per context; retain identities across copies and four physical backing patterns |
| CT5 | The selected instruction semantics are adequate | Symbolic certificates | Compare every computed register, NZCV, read and write with an independent A64 interpreter; unsupported operations fail closed |
| CT6 | The four explicit representations delimit finite path coverage | Counts and concrete endpoints | Preserve relocation-dependent paths/counts; arbitrary stack/image relocation remains unproved |
| CT7 | Original readable segment tails begin zero in the fresh-image model | Word read at0x1010C8258 | Verify Mach-O zero-fill metadata, replay loader bytes and recover earlier/native writers separately |
| CT8 | Comparison records are valid aligned 48-byte objects; caller uses its recovered frame geometry | Compact helper/caller ABI | Prove field codecs and all-u64 comparisons, and check a nonempty domain witness |
| CT9 | Authenticated pointer metadata identifies static targets | Internal call and entropy boundary | Decode original format12 words/key/diversity; hardware PAC success remains unknown |
| CT10 | Installed SDK declaration supplies the stated entropy signature | Zero-argument import interpretation | Rehash `_stdlib.h`; native provider implementation/output remains outside this increment |
| CT11 | Private copies do not initialize their input bits or establish an external wire schema | Data-flow and IPC classification | Track byte identities/knownness; require an actual transport call before assigning a message/right role |
| CT12 | This increment extends selected initialization paths only | Coverage and continuation | Continue entropy return/state consumers, nonzero control branch and actual IOKit/Mach paths; full objective remains active |

## Context movement and unknownness

The first transfer reads u64 fields at F-relative offsets `0x5A8,0x448,0x4B8,0x4A0,0x468,0x4A8,0x3F8,0x510,0x458,0x530,0x528,0x480,0x4C0,0x588`. Here F is callback SP after its 3,040-byte prologue. Several values are copied into private scratch slots, carried in registers and copied back. Their knownness remains zero throughout those copies. Source stores of newly defined values are treated separately. [CT2-CT5]

| Original field offsets | State at first entropy boundary |
| --- | --- |
| 0x4A0,0x468,0x4A8,0x480,0x4C0,0x588 | Preserve the same eight unknown byte identities at each original field |
| 0x5A8 | Source-defined pointer F+0x3B4 |
| 0x448,0x4B8 | Source-defined arena base H |
| 0x3F8,0x510,0x458,0x530,0x528 | Source-defined addresses within H's 90,000-byte owner; object schemas/request sizes remain unassigned |

For the first representation, the latter five arena-relative values are H+`0x15CEC`, H+`0x15D1C`, H+`0x15D54`, H+`0x15D1C`, H+`0x15D34`. These are observed source values under the declared allocator return. They are not five additional native malloc results. The contracts retain each representation's exact values. [CT2,CT6]

The certificate language admits only literal bytes or identities of the original unknown bytes. Every branch target/address is concrete, unknown private copies retain origin terms, and unknown writes outside the private stack are rejected. At the final boundary all 31 X registers are concrete expressions independent of the 112 unknown inputs. Unknown bytes still remain in private memory. [CT3-CT5,CT11]

| F / H representation | New source visits | Four-byte generator store visits | Other scalar byte-generator store visits |
| --- | ---: | ---: | ---: |
| F=0x640000B420, H=0x6500000000 | 31,032 | 8 | 700 |
| F=0x640000B420, H=0x6500100000 | 31,032 | 8 | 700 |
| F=0x640000B520, H=0x6500000000 | 32,344 | 8 | 732 |
| F=0x640000B520, H=0x6500100000 | 32,344 | 8 | 732 |

These are instruction/store observation counts, not durations or counts of distinct initialized bytes. The stack placement changes real source paths and generator lengths. No PRNG or cryptographic algorithm name is assigned to those byte generators. [CT6]

## Complete 48-byte comparison-record contract

The internal call is at `0x1002DC178`, through original slot `0x10109FD20`, IA diversity `0xEC9D`, target `0x10041A5E0`. It passes X0=R, with R=FP-`0xD8`=F+`0xAF8`. The leaf uses no stack frame, calls no other function and has 36 source instructions including RET. It writes only four bytes at R+`0x10`; X0 remains R. This is a private record ABI. [CT8,CT9]

Define exact modular keys:

```text
K = u64((R XOR 0x4DE3A292F9D49974) * 0xDA51A827)
k = low32(K)
```

The caller's original producer at `0x10032C960..0x10032C9A4` supplies the same prekey through F+`0x138`. The helper's OR/AND/subtract prekey normalizes to the XOR expression above, under an independently proved source lemma. The odd multiplication has inverse `0x4355E95E8F154797` modulo 2^64. This is an address-dependent codec; no cryptographic property is inferred. [CT8]

| Record offset | Width | Decoding / role |
| --- | --- | --- |
| +0x00 | u32 | mode=u32(raw-k); only bit0 selects comparison |
| +0x04..+0x07 | 4 bytes | Unread by this helper |
| +0x08 | u64 | A=u64(raw-K) |
| +0x10 | u32 | Output, overwritten by helper |
| +0x14 | u32 | mask=u32(raw-k) |
| +0x18..+0x1F | 8 bytes | Unread by this helper |
| +0x20 | u64 | B=raw XOR K |
| +0x28 | u32 | false_choice=u32(raw+k) |
| +0x2C | u32 | true_choice=raw XOR k |

The complete semantic result is:

```text
choose = (mode & 1) ? unsigned_u64(A) > unsigned_u64(B) : A == B
record.result = mask XOR (choose ? true_choice : false_choice)
```

Both modes cover arbitrary u64 operands and arbitrary u32 mask/choices. The routine has a fixed instruction sequence with conditional selects; that does not establish hardware timing properties. The accessed extent is 48 bytes; unused fields receive no semantic names. Cost is O(1) time and space. [CT8]

## Caller control word and exact continuations

The caller reads u32 C from `0x1010C8258`, supplies decoded mode=0, A=0, B=zero_extend_64(C), and uses recovered phase P=`0x61F6DA56`. Decoded mask is u32(P-`0xD3E`), true choice P, and false choice u32(P+`0x3E`). Thus the original caller/helper composition gives:

| C | Result/table index | Original slot | Target selected after call |
| --- | --- | --- | --- |
| 0 | 0x174E | 0x101045960 | 0x1002729F8 |
| Any nonzero u32 | 0x178C | 0x101045B50 | 0x10031CC98 |

Both continuation slots use IA diversity `0x504C`, address-diversity zero. The caller consumes the result using LDURSW before indexed dispatch. Its two proven indices are positive; generic outputs of other helper callers are not constrained to these values. The nonzero continuation's further behavior remains unestablished here. [CT8,CT9]

The control word lies in original `__DATA,__common`, section flags low byte 1 (`S_ZEROFILL`). The selected executions apply the fresh-image zero-fill rule and observe C=0. This is a loader/environment premise, not a live daemon observation or proof that earlier process code cannot change the word. Its operational meaning and complete writer set remain unknown. [CT7]

## First entropy interface and evidence limits

```text
original callback/arena prefix
    -> unknown-preserving context copies and source byte generators
    -> encoded comparison record: zero versus image control word
    -> selected zero-word continuation and further source context work
    -> 0x100409574: arc4random boundary
```

The import resolves through the original byte bank and authenticated binding retained in the contracts. The installed SDK `_stdlib.h:287` declares `uint32_t arc4random(void);`. The call has zero arguments and a u32 result. X0 at the boundary still contains a context address; it is not an arc4random argument or a port name. The entropy provider and result are not executed or modeled in this increment. The callback has not returned and no IOKit/Mach emission is added. [CT9-CT12]

All checks pass: four symbolic contexts cover 126,752 source visits with 112 unknown bytes each; sixteen independent A64 replays cover 507,008 visits, 457,856 register effects, 213,936 read bytes, 119,424 write bytes, 12,288 NZCV effects and 3,456 copied-unknown byte effects. Four prefix states and four additional transfer cases are freshly replayed. Ten source proof pairs cover 126 lifted instruction visits across six slices, including two lifts of the same comparison body. Forty original fixups, 512 exhaustive bank inputs, 470 current IDA rows and the SDK signature are checked. [Checks](triage_evidence/daemon_context_transfer_checks.json), [preservation](triage_evidence/daemon_context_transfer_preservation.json), [scoped gates](triage_evidence/daemon_context_transfer_quality_gates.json).

| Impact | Next question | Evidence required |
| --- | --- | --- |
| High | Entropy return and later state consumers | Carry a declared u32 result through original writes, further entropy/time calls and initialization state |
| High | Control-word writers and nonzero continuation | Recover all feasible writers/earlier initialization and follow 0x10031CC98 |
| High | Private arena-relative object interfaces | Recover requested extents, record fields, producer/consumer ABI and lifetime of the new addresses |
| High | Actual daemon/kext transactions | Continue source-produced initialization through IOKit/Mach caller records and emission sites |
| Medium | Address-dependent byte generators | Recover compact byte functions/loop bounds across further representations without erasing observed variation |

The symbolic certificate and replay cost O(C*(B+V+events)) time/retained output, with working space bounded by the largest trace, byte-memory state and expression DAG. The compact helper lift is O(I) DAG time/space; solver timeout is 30 s/query. Unsupported instructions, unknown-dependent targets/addresses and non-copy unknown byte expressions fail closed.

QG1 passes for factual analysis. QG2 passes with CT1-CT12. QG3 passes for this increment; the full objective remains active. QG4 passes for u32/u64 wrapping, 48-byte record layout, 112-byte unknown domain and explicit counts. QG5 passes with copied unknownness, source-defined values, loader premises, entropy signature and finite representation coverage distinguished. QG6 passes for original bytes, fixups, byte-origin certificates, independent A64 effects, source proofs and SDK provenance. QG7 passes with the bounded impact-labeled continuation table. Native entropy output, actual global state, remaining context/object semantics and downstream transport remain unknown.

Reproduction uses the Python/Z3 environment from the preceding reports: run `probe_daemon_context_transfer.py`, `replay_daemon_context_transfer.py`, `recover_daemon_context_transfer.py`, `prove_daemon_context_transfer.py`, then `validate_daemon_context_transfer.py`, with `PYTHONPATH=triage_evidence` and installed Python bindings for Z3, Capstone and Unicorn; configure `Z3_LIBRARY_PATH` for the installed Z3 runtime if required.
