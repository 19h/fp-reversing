# Conditional network-identity record and shared acquisition boundary

The positive process-path continuation conditionally calls `0x10044167c`, a network-identity record adapter. Under three additional initializer-compatible pointer-cell premises, its original call at `0x1004418a8` reaches the network cache helper `0x1000040a8`. Separate warm-cache controls copy six bytes into a global length/data record at `0x1010c5764` and publish its address through the caller's temporary record. The caller preserves that address before reusing the temporary for the previously recovered acquisition adapter `0x10043e280`. [NR1-NR4]

The retained eight undefined-root stops remain unchanged. The first continuation needs three new root-cell premises; the later acquisition continuation needs two further bank roots and an explicit zero-valued image-controller premise. The initializer and caller are separate execution epochs. No native process-path-to-network join, identity freshness, actual synchronization or daemon-kext transaction is established. A separate zero-network-return premise restores the additional 32 B cursor reservation and reaches saved continuation `0x100671718`. [NR2-NR5]

```text
Frozen positive path -> STOP before undefined S+0x858
  + separate root premises S+0x858, S+0x5f0, S+0x5e0
  -> call 0x1005c524c: network-record adapter(C)
       -> call 0x1004418a8: network-cache helper(S-0x6e)
       warm cache fixture -> six local bytes
         -> global record: u32 length 6 | bytes[6]
         -> C+0 := address of global record
       separate low32 zero-return premise
         -> C+0 := NULL

Caller consumes C+0
  NULL -> restore inner 32 B cursor -> saved continuation 0x100671718
  non-NULL -> save pointer at S+0x998; reuse C for acquisition record
    -> STOP before undefined S+0x5d0
    + two bank-root premises and controller-image premise
    -> acquisition adapter 0x10043e280
    -> STOP at pthread_once(0x1010b8cd0, 0x10040ebd4)
```

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| NR-A1 | The pinned thin daemon and unchanged parent receipts identify this source. Every address claim depends on that identity. | Rehash source, dependencies, original fixups and retained boundaries; do not infer native build/task/provider pairing. |
| NR-A2 | Initializer-compatible root values are new caller premises. All conditional continuations depend on these additions. | Verify five original writers and nonoverlapping lifetime in all twelve frozen initializer profiles, then replay each under two backing patterns. Keep the initializer/caller epoch join unproved. |
| NR-A3 | Cold/warm readiness, cache bytes and record-neighbor bytes are explicit image fixtures. Cache continuations depend on them. | Check eight zero-flag cold entries, then four six-byte patterns, flags 1/3/255 and all eight parent contexts; compare output bytes, guards and source copy/return channels. No native MAC value is supplied. |
| NR-A4 | The low32-zero internal-component return is a separate cut premise; callee output effects are unmodeled. Zero-branch controls depend on that boundary. | Preserve callee-saved state/SP, clobber caller-saved registers/flags, leave local output bytes undefined and prove that this branch reads none of them. This is not an original complete network-helper failure execution. |
| NR-A5 | The acquisition continuation explicitly defines the u64 image controller at `0x1010b66a8` as zero. Its pending-once result depends on that additional environment premise. | Keep it absent until the final bank-root cut, verify the exact added bytes and source-derived later updates, and independently replay every image read/write. Native initialization of that controller remains unknown. |
| NR-A6 | Logical PAC instructions and authenticated edges use exact original pointer/slot provenance. Cut-state replay depends on the carried origin. | Verify the frozen pre-cut table read, original target/modifier word and every later edge; model PACIZA as logical pointer preservation. Hardware authentication does not execute. |
| NR-A7 | Formal record-decoding claims use their stated address domains. Acquisition decoding composes a key-agreement lemma. | Prove network decoding for all SP64, exact acquisition prehash agreement iff `(SP & 6)==0`, then compose an arbitrary common prehash key. The actual SP values are 16 B aligned. |
| NR-A8 | Current SDK declarations compare the pending once ABI; earlier acquisition analysis supplies separate context. API interpretation depends on those pinned sources. | Compile prototype/width checks, retain relative-header hashes, and compare the exact control/callback tuple with the unchanged synchronization report. Do not import its callback effects into these cases. |
| NR-A9 | Publication changes only its owned paths. Preservation claims depend on exact manifest comparison. | Check original inputs, source/receipt pins, unchanged entries, archive round trips and raw/typed/decoded-payload path hygiene. |

## Root writers and admission cuts

Let S denote the caller's large-frame SP. The twelve earlier initializer profiles use their own frame base F; equal offsets do not identify the same frame lifetime. Each profile has exactly one overlapping eight-byte store to each field below and no later overlap before its original boundary. Fresh independent replays check all five values at those boundaries under two backing patterns. [NR2-NR3]

| Field | Original writer | Source-produced value | Additional caller use |
| --- | --- | --- | --- |
| F+`0x858` | `0x1004c2d30` | `0x1010c8268` | Cache-pointer-cell address; first retained unknown root |
| F+`0x5f0` | `0x1004c25cc` | `0x101031da0` | First network-adapter selector bank |
| F+`0x5e0` | `0x1004c3480` | `0x100e99900` | Second network-adapter selector bank |
| F+`0x5d0` | `0x1004c26b0` | `0x100e99800` | First later acquisition selector bank |
| F+`0x5d8` | `0x1004c26c8` | `0x100f4e290` | Second later acquisition selector bank |

Every added caller root replaces exactly eight undefined bytes at its original stopped read. Registers, flags and all other declared/source-defined bytes are preserved across each cut. The first three cuts start at `0x1005a8cd4`, `0x1005c5208` and `0x1005c5220`; their original continuations execute 92, 6 and 152 visits respectively before the network-helper entry. No source initializer-to-caller control-flow edge is added. [NR2-NR3]

The later `0x1010b66a8` controller is a separate eight-byte zero premise, not a sixth recovered stack root or an original-file value. Independent replay identified that the inherited harness initialized it without retaining a fixture ledger entry. This increment declares the exact value at the acquisition cut and verifies its subsequent source writes. It does not change earlier receipts or treat their unused bytes as native observations. [NR2-NR3]

## Network record ABI and source decoding

Let C=`u64(S+0x10cb8)`. The source reuses the temporary record previously used for the signed process-path comparison. The call at `0x1005c524c` passes X0=C through original table index `0xcd0f`, slot `0x1010a0768`, IA diversity `0xc662`, to entry `0x10044167c`. The adapter reads only four bytes at C+8 for its control and later writes the returned pointer into C+[0,8). Its accessed record extent is 12 B; no allocation size or complete C structure is inferred. [NR2-NR3]

The caller's `0x1005c5184..0x1005c51dc` construction and the adapter's `0x1004417bc..0x1004417f8` decode compose to W26=`0x7657` for every SP64, without an alignment premise. The `0xbe9` subtractive bias is part of the caller's encoded control. The source proof includes that bias; the decoded value is not the intermediate W22=`0x8240`. [NR2-NR3]

The adapter reserves 112 B, so its inner SP is Q=S-`0x70`. It calls the network helper with X0=Q+2=S-`0x6e` through index `0xcf05`, slot `0x1010a1718`, IA diversity `0xe9e4`. Q+[2,8) is the six-byte local output. The network helper's own 64 B frame is separate. Warm controls execute its complete original return; no imported API executes. [NR2-NR4]

| Network low32 return | Original selector index | Target | Result channel |
| --- | --- | --- | --- |
| Zero | `0x7657` | `0x10020eb48` | X20 remains NULL; write u64 zero at C+0 |
| Nonzero | `0x7677` | `0x100268010` | Build static length/data record, then publish its pointer |

The predicate uses W0 only. It does not require readiness equal to 1. Original warm-cache returns 1, 3 and 255 all select publication. The [network helper report](daemon_network_identity_report.md) already distinguishes cache-flag readiness from native freshness and missing-property zero-status behavior. This increment supplies four six-byte cache patterns; it does not establish a fresh property read. [NR2-NR4]

## Static length/data record and pointer return

| Address / source site | Width | Established role |
| --- | --- | --- |
| `0x1010c5764` / store `0x100268064` | 4 B | Little-endian length 6 |
| `0x1010c5768` through `0x1010c576d` | 6 B | Identity bytes copied from Q+2 |
| Call `0x1002680d4` | X0=Q+2, X1=`0x1010c5768`, W2=6 | Original copy helper `0x10046f89c`; IA diversity `0x34a1` |
| Store `0x10020eb48` | 8 B at C+0 | X20=`0x1010c5764`, or NULL on the zero-return branch |

The ten bytes above are the accessed record prefix, not a recovered allocation extent. The source writes the length before the six data bytes. The copy uses six original one-byte stores, and the common epilogue restores the adapter's saved registers and SP before returning to `0x1005c5250`. X0 is residual machine state; the caller obtains the result from C+0. A pointer publication does not establish ownership, lifetime or external exposure. [NR2-NR3]

Ninety-six warm controls cross eight retained parent contexts, three nonzero readiness values and four byte patterns: all zero, all `0xff`, `0123456789ab` and `80017fff00fe`. They preserve four declared guard bytes on either side of the ten-byte accessed prefix. All record bytes match the selected cache pattern exactly. The pointer value is unchanged across patterns. These are private source controls, not observed hardware addresses. [NR2-NR3]

## Caller storage epochs, cursor and acquisition record

At `0x1005c5250`, the caller loads the u64 result from C+0. The source predicate selects table index `0x8240` for non-NULL, or `0x8468` for NULL, under the recorded phase/control values. The latter reaches `0x10084ac58`: it subtracts 32 B from the cursor at S+`0x16d0`, reloads the saved continuation and eventually branches to `0x100671718`. The cursor is then the parent's U+`0x420`, preserving the preceding 1,056 B reservation. This increment stops before that saved continuation's body; it does not claim full scratch retirement. [NR2-NR3]

The inner reservation was introduced by the conditional prefix at `0x1004dbdf0..0x1004dbe5c`: its cursor advances by `0x20` from U+`0x420` to U+`0x440`. This is cursor bookkeeping under a private arena premise, not a native allocator or an allocation of the static network record. Eight separate zero-return controls execute 19 adapter-return visits and 147 caller/restoration visits each. They do not read the undefined local six-byte output. [NR2-NR3]

The non-NULL branch preserves the network-record address at S+`0x998`, via store `0x1004f7464`, before reusing C. Store `0x1004f7460` also reuses S+`0x9b8` for the current X21 pointer, S+`0x103db`; that cell's earlier integer/pointer roles do not define a permanent field type. The new record has these accessed fields. [NR2-NR3]

| Acquisition temporary field | Width | Source-defined role |
| --- | --- | --- |
| C+`0x00` | 4 B | Address-keyed encoded control; decodes to `0x593d` under the stated key domain |
| C+`0x04` | 4 B | Untouched gap; not read by the inspected acquisition prefix |
| C+`0x08` | 8 B | Zero captured-pointer operand, written by `0x1004f74c0` |

The acquisition prefix accesses a 16 B span with 12 B of relevant fields. The gap retains earlier bytes; it is not silently initialized. Exact source equations establish agreement of the caller/helper prehash keys iff `(SP & 6)==0`. Both keys then use the same u32 multiplier `0x316f29c1`. A separately checked composition with an arbitrary common prehash key proves decoded control `0x593d` and captured pointer NULL. The actual SP values are 16 B aligned and satisfy the domain. The composed proof avoids repeating a difficult multiply/XOR bit-blast; a solver timeout is not treated as proof. [NR2-NR3]

The new root at S+`0x5d0` is first needed at `0x1004f74f8`, after 73 caller visits; S+`0x5d8` is next needed at `0x1004f750c`, after five further visits. With those roots and the explicit controller image, the next 174 visits call acquisition entry `0x10043e280` at `0x1004f7538` and stop at its original `pthread_once` call. The process-path buffer is not read by any of the 96 warm continuations. This source slice therefore establishes environmental record production and shared initialization linkage, not interpretation of native path strings or identity policy. [NR2-NR3]

## Shared initialization interface and port accounting

| Interface | Original location | Established call/operand |
| --- | --- | --- |
| Acquisition entry | `0x1004f7538` | Index `0xcbf3`, slot `0x10109fe88`, IA diversity `0x6aa4`; X0=C |
| Once primitive | `0x10043e508` | `pthread_once(control, callback)`; W0 return remains pending |
| Once control | X0 at pending call | `0x1010b8cd0` |
| Callback | X1 at pending call | `0x10040ebd4`, after logical PACIZA at `0x10043e4f8` |
| Captured pointer | Saved X19 at pending call | NULL, from acquisition record C+8 |

The control/callback tuple and acquisition entry match the earlier [IOKit synchronization report](daemon_iokit_sync_report.md), which separately analyzes primary/fallback selection, once callback and lock interfaces. This increment does not execute the once implementation, callback or a lock, and does not import earlier fixtures' effects into the new cases. Identical code and control-cell addresses do not establish a shared native invocation, completed once state or valid lock object. [NR2-NR3, NR5]

The current arm64e SDK declares `pthread_once(pthread_once_t*, void(*)(void))` returning int; its compared control type occupies 16 B. Compile-only verification retains the exact assertions and assembly. The SDK type size does not prove the historical native control object's allocated extent. [NR3, NR6]

The global identity-record pointer, cursor, saved continuations, once control and callback are process-local channels, not recovered Mach names. Warm controls execute no IOKit import and add no native Mach send/receive, right disposition, retirement or message-emission site. The conditional network entry retains the API port-output sites established in the [network helper report](daemon_network_identity_report.md); API-internal transport and actual daemon-kext transaction identity remain unknown. [NR2-NR6]

Eight separate cold controls declare readiness=0 at the network-helper entry. Each executes twelve original instructions and stops at direct call `0x1000040d8`, before the import stub or API. Its arguments are W0=0 and X1=S-`0xb0`, the network helper's inner SP after the adapter's 112 B and helper's 64 B frame reservations. The compared SDK identifies a four-byte `mach_port_t` output at that address. This is a caller-specific API output location, not an observed port name, native right or Mach-message emission. [NR2-NR4]

## Provenance and verification

| ID | Primary evidence / role |
| --- | --- |
| NR1 | Original thin daemon SHA256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; preferred virtual addresses throughout. |
| NR2 | [Extractor](triage_evidence/recover_daemon_network_record.py) and [checks](triage_evidence/daemon_network_record_checks.json.zst): source slices, selector banks, original fixups, root-writer lifetimes, declared cut effects and strict source journals. |
| NR3 | [Independent auditor](triage_evidence/audit_daemon_network_record.py) and [audit](triage_evidence/daemon_network_record_audit.json.zst): scalar register/flag/byte replay, fresh initializer execution, exact state joins and SDK compilation. |
| NR4 | Frozen [network helper checks](triage_evidence/daemon_network_identity_checks.json.zst) and [audit](triage_evidence/daemon_network_identity_audit.json.zst), with the [network report](daemon_network_identity_report.md): retained states, cache/helper bodies, IOKit import/stub/SDK evidence and separate nested controls. |
| NR5 | Frozen [initializer checks](triage_evidence/daemon_return_bank_origins_checks.json.zst), [bank-origin report](daemon_return_bank_origins_report.md), and earlier [synchronization analysis](daemon_iokit_sync_report.md): separate source epochs and shared acquisition/once interface context. |
| NR6 | Current SDK pthread headers and the earlier IOKit headers; exact compile source, arm64e assembly and relative-header hashes are retained in NR3/NR4. Historical runtime pairing remains unknown. |
| NR7 | [Publication verifier](triage_evidence/verify_daemon_network_record_publication.py): source/receipt pins, exact owned delta, original-input preservation, archive round trips and raw/typed/decoded-payload path hygiene. |

Eight conditional parent contexts, eight cold-cache controls, 96 warm controls and eight zero-return controls yield 432 new intervals, 39,616 source visits, 9,128 reads, 3,488 writes and 1,008 logical edges. Eight source queries are UNSAT, with nonvacuous domains. Three complete 256-input selector identities establish the network adapter, network helper and acquisition adapter targets. The zero-return controls remain distinct from complete network-helper execution. [NR2-NR3]

Independent new-path replay checks 1,281,536 register values including SP, 40,048 NZCV values, 50,040 read bytes, 22,112 write bytes and 712 authenticated edges. It additionally verifies eight authenticated entry origins and sixteen saved-continuation origins. There are 216 exact added-root joins, eight cold main-port joins, 96 additional-controller joins, 96 warm-record joins and eight zero-return/restoration joins. The current SDK compile succeeds. [NR3, NR6]

Twenty-four fresh initializer replays check 42,792 source visits, 8,872 reads, 5,672 writes, 43,240 read bytes, 36,360 write bytes and 168 logical edges. They verify 120 terminal root values across five fields, twelve profiles and two backing patterns. Every original writer and absence of later overlapping writes is also checked in the frozen source journals. This is within-profile lifetime evidence, not a native cross-epoch join. [NR2-NR3]

The auditor carries an authenticated target loaded before the first cut from the exact frozen read at table index `0x58d7`. It separately validates saved continuation cells S+`0x2a60` and S+`0x4bb0` against original slots `0x4ca` and `0x100b`, their original stores and unchanged intervening state. A recent authenticated load of another pointer cannot substitute for that saved origin. PACIZA preserves only the logical callback address in this model. [NR2-NR3]

The fixed six-byte publication and adapter records use O(1) time and storage per invocation. Source extraction/audit use O(E+C*(I+W)+S+Q) time and space for receipt bytes E, cases C, visits I, effects W, captured source S and queries Q, excluding solver cost; queries have a 30 s limit. Large JSON is compressed with zstd level 22 and checked by exact decompression. [NR2-NR3, NR7]

## Bounded continuation

| Impact | Open interface / pattern | Discriminating evidence |
| --- | --- | --- |
| High | Real initializer-to-caller root lifetime | Uninterrupted same-frame execution and all overlapping writes; preserve the original eight undefined-root boundaries until that join exists. |
| High | Native path, identity and transaction context | Same-build token/PID/path results, ordered network-property/cache observations and actual provider/connection/request identity; these private fixtures establish none of those identities. |
| High | Shared acquisition continuation | Continue the exact pending once boundary with explicit once/callback/lock premises, then establish the selected fallback-pointer producer and lifecycle; equal tuple addresses alone do not import earlier native state. |
| Medium | Global record visibility and lifetime | Establish synchronization, consumers and concurrent writes before assigning stable ownership or atomic publication to the length/data prefix. |
| Medium | Cache success/freshness separation | Distinguish full flag-byte nonzero from bit-zero readiness and fresh six-byte property writes across complete cold calls. |
| Medium | Temporary record/storage epochs | Track C's comparison, network-pointer and acquisition layouts, including untouched gaps, and subsequent use of saved S+0x998. |
| Low | General address domains | Extend control/key equations to additional source callers only after deriving their own constants and exact alignment domains. |

## Scoped quality gates

**QG1** passes for factual source/interface analysis. **QG2** passes with NR-A1..NR-A9. **QG3** passes for this increment's routine roles, caller-specific port-output boundary, pointer/data records, control flow, cursor handling and shared initialization interface; the full goal remains active.

**QG4** passes with accessed byte extents, explicit u32/u64 channels, modular keys, frame offsets and complexity. **QG5** passes within scope: initializer epochs remain separate, the extra controller is declared, zero-return cuts are not complete callee executions, gap bytes remain untouched and acquisition decoding is domain-qualified. **QG6** passes with pinned source/fixups, independent new-path and initializer replay, exact cut-state joins and current SDK compilation. **QG7** passes with the impact-ranked continuation table. No native API, IPC, allocation/free, hardware PAC or IDB mutation executes. [NR1-NR7]
