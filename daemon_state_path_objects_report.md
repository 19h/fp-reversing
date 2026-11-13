# SIDB state-path object, private rwlock and failure cleanup

The daemon's pending74 B allocation constructs a local object containing `/var/db/fpsd/SC Info/SC Info.sidb`. Under separate nonnull allocation and zero `pthread_rwlock_init` return premises, original source defines63 B, leaves11 B undefined and then publishes the object pointer at J+`0x118`. A separate200 B allocation supplies its rwlock. Failure paths preserve J+`0x118`; failures after the74 B allocation request its free. All48 retained continuations reach the next74 B request for J+`0x120`. No file-open operation or native daemon-kext exchange is established by these paths. [SO1-SO6; SO-A1-SO-A10]

```text
pending malloc(74), destination J+0x118
  + NULL --------------------------> status 0x74c29d85
  + nonnull B -> local rwlock creator -> pending malloc(200)
                 + NULL ----------> free(B) -> status 0x74c29d85
                 + nonnull L -> clear8 -> pthread_rwlock_init(L,NULL)
                                + nonzero -> free(B) -> mapped status
                                + zero -> private cell receives L
                                           -> initialize B header/path
                                           -> publish B at J+0x118
                                           -> status 0x8b3dc651
  all retained returns -> next record -> pending malloc(74), J+0x120
```

| Evidence | Primary artifact and scope |
| --- | --- |
| SO1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [extractor](triage_evidence/recover_daemon_state_path_objects.py) retains source bytes, logical fixups, full GP/Q/flags states and byte events. |
| SO2 | [Payload-reactivation report](daemon_payload_reactivation_report.md), [checks](triage_evidence/daemon_payload_reactivation_checks.json.zst) and [audit](triage_evidence/daemon_payload_reactivation_audit.json.zst): four exact pending-allocation states, encoded directory input and existing caller fields. |
| SO3 | [Current checks](triage_evidence/daemon_state_path_objects_checks.json.zst): four parents crossed with two ABI patterns and six allocation/initializer scenarios,200 intervals. |
| SO4 | [Independent auditor](triage_evidence/audit_daemon_state_path_objects.py) and [audit](triage_evidence/daemon_state_path_objects_audit.json.zst): source replay, exact return/owner/opacity joins, full object comparisons and11 nonvacuous source equations. |
| SO5 | [Rwlock lifecycle report](daemon_rwlock_lifecycle_report.md), [contracts](triage_evidence/daemon_rwlock_lifecycle_contracts.json.zst) and [source equations](triage_evidence/daemon_rwlock_lifecycle_symbolic.py): recovered creator, allocation/initializer bindings, SDK evidence and all-u32 status/publication predicates. Two source predicates are rebuilt and rechecked here. |
| SO6 | [Publication verifier](triage_evidence/verify_daemon_state_path_objects_publication.py): current source/dependency pins, exact coverage, rebuilt proof expressions, all packed-payload path checks, original-input preservation and manifest delta. |

## Allocation, call records and private lock destination

Use J=`0x6500115b20`, B=`0x6600006000` for the declared74 B allocation and L=`0x6600007000` for the separate200 B allocation. Nonnull returns add exactly those initially undefined owners. Restoring an empty owner maps backing pages without defining bytes or adding a duplicate owner. Neither native malloc nor a native synchronization API executes. [SO1-SO4; SO-A1-SO-A4]

The first imported malloc is at `0x10018ed34`, IA modifier `0x6aa4`, X0=74. Its return gate `0x10018ed38..0x10018ed60` partitions the full64-bit pointer at zero under the inherited phase. NULL selects `0x1000354d4`; nonnull selects `0x10006eb78`. The nonnull branch saves B at SP+0 and builds a new20 B accessed lock-creation record at C=SP+`0x40`. It calls `0x10006ec54 -> 0x10043a240`, IA`0x8c6d`. This is the known creator with a new private destination, not either global destination in the earlier paired-global caller. [SO1,SO3-SO5; SO-A3-SO-A5]

| Lock record field | Width | Original source | Contract |
| --- | --- | --- | --- |
| C+0 | 4 B | `0x10006ebd0` | `0xaed7-k`, modulo2^32; `k=(low32(C) XOR 0xdc40790b)*0x5973a279` |
| C+4 | 4 B | No new record write | Gap; no source type assigned |
| C+8 | 8 B | `0x10006ebd8` | Address SP+`0x30` of the creator's output-pointer cell |
| C+16 | 4 B | Creator `0x1001c0128` | Raw creator status |

For these calls SP=`0x6800060040`, C=`0x6800060080`, and the destination cell is `0x6800060070`. The creator subtracts its own112 B frame before its body. Source `0x10019385c` requests malloc(200), with IA`0x6aa4`. A nonnull L receives four two-byte zero stores at `0x100130f70`, `0x100130f74`, `0x100130f78` and `0x100130f7c`, defining only its first8 B. At `0x100130fcc`, the imported binding is `pthread_rwlock_init`, X0=L, X1=0, IA`0xa027`. All200 bytes are then explicitly invalidated as opaque library state for every declared initializer return. Zero permits creator store `0x1002097dc` to publish L into the private output cell. No lock-object byte is read by the subsequent retained source. [SO1,SO3-SO5; SO-A4-SO-A5]

## Source-defined object layout

After successful lock creation, source `0x1000fc570` reloads the private lock pointer and `0x1000fc578` reloads B. Header stores precede path construction. [SO1,SO3-SO4; SO-A5-SO-A7]

| Offset from B | Width | Established bytes/role | Source store |
| --- | --- | --- | --- |
| +`0x0` | 8 B | Raw L pointer | `0x1000fc580` |
| +`0x8` | 8 B | Zero u64 | `0x1000fc580` |
| +`0x10` | 8 B | Zero u64 | `0x1000fc584` |
| +`0x18` | 1 B | `01`; field meaning unknown | `0x1000fc57c` |
| +`0x19` | 3 B | Undefined gap | No retained write |
| +`0x1c` | 4 B | Zero u32; field meaning unknown | `0x10003a3dc` |
| +`0x20` | 20 B | `/var/db/fpsd/SC Info` | Directory loop `0x1000879d8` |
| +`0x34` | 1 B | `/` | `0x1000fe480` |
| +`0x35` | 12 B | `SC Info.sidb` | Four stores per group at `0x10009162c/638/648/658` |
| +`0x41` | 1 B | NUL | `0x10003a3d8` |
| +`0x42` | 8 B | Undefined tail | No retained write |

The header has29 defined bytes and3 undefined bytes. The path has20+1+12+1=34 B including NUL. Thus29+34=63 defined bytes and3+8=11 undefined bytes account for the complete74 B owner. The last defined byte is B+`0x41`; exclusive written end is B+`0x42`. Source access establishes this local layout and allocation request, without assigning a native structure name, stream-handle type, ownership transfer or filesystem state. [SO1,SO3-SO4; SO-A6-SO-A8]

## Directory and basename provenance

The inherited21 B input owner at `0x6600003000` contains the directory plus NUL, each byte XOR`0x98`. Its exact retained bytes are `b7eef9eab7fcfab7fee8ebfcb7cbdbb8d1f6fef798`; no cleartext directory fixture is added by this increment. The original constructor prefix determines directory length20 before the first malloc. The current loop reads encoded bytes19 down to0 at `0x1000879cc` and stores decoded bytes at B+32+index through `0x1000879d8`. Under the retained control words, the original AND/EOR/EOR sequence is byte XOR`0x98` for every8-bit input. The source does not copy the input terminator as part of that20-byte loop. [SO1-SO4; SO-A2,SO-A6]

The filename comes from original file-backed bytes at `0x10102fa20`, not the encoded directory owner. The12 accessed bytes are `7d6b01b9580c3cf6574021fd`. For each four-byte input group e0,e1,e2,e3, the actual source emits `(e2 XOR 0x52),(e0 XOR 0x3e),(e3 XOR 0x99),(e1 XOR 0x22)`. Three arbitrary-data source proofs cover the executed group offsets0,4,8. Their concrete outputs are `SC I`, `nfo.` and `sidb`. The following source store supplies the NUL independently. Additional bytes near the filename constant are not used to infer a larger input extent or type. [SO1,SO3-SO4; SO-A6-SO-A7]

The pathname is recovered target ABI/state evidence and contains no analyst username. It is not an observation that the file exists, was opened, was created, was authorized, or reached the kext. External control of either source input in a native caller remains unknown. [SO1-SO6; SO-A8-SO-A10]

## Publication, results and failure cleanup

Only after header, directory, separator, filename, terminator and zero-u32 writes does `0x10003a3e0` store the full B pointer through the caller destination J+`0x118`=`0x6500115c38`. No current source read dereferences B; initialization and local publication do not establish native exposure. The constructor stores raw status at request+8 through `0x1000354d4`, then returns to `0x1004cef34`. [SO1,SO3-SO4; SO-A7-SO-A9]

| Retained outcome | Constructor status32 | B publication | Later retained imported request |
| --- | --- | --- | --- |
| First malloc returns NULL | `0x74c29d85` | None; old J+0x118 preserved | Next malloc(74) |
| Lock malloc returns NULL | `0x74c29d85` | None | free(B), then next malloc(74) after a declared void return |
| Initializer returns0 | `0x8b3dc651` | B at J+0x118 | Next malloc(74) |
| Initializer returns12 | `0x74c29d85` | None | free(B), then next malloc(74) after a declared void return |
| Initializer returns16 | `0x74c29d82` | None | Same cleanup route |
| Initializer returns22 | `0x74c29d83` | None | Same cleanup route |

The recovered all-u32 creator predicate maps0 to `0x8b3dc651`,12 to `0x74c29d85`,16 to `0x74c29d82`, and every other u32 to `0x74c29d83`; only zero publishes L. That complete source theorem is rechecked here. Concrete current continuations retain0,12,16,22; they are separate API premises, not observed native error outcomes. [SO3-SO5; SO-A4-SO-A5]

Failure after B allocation reaches `0x100085acc`, imported free, X0=B, IA`0x46a2`. The declared void return retires exactly the74 B owner. No later retained access touches that span. These initializer-failure paths do not request a separate free of L before the next allocation frontier. That is a bounded source ordering observation; native cleanup, complete lifetime and a native resource leak remain unknown. No failure path writes J+`0x118` or defines a B payload byte. [SO1,SO3-SO5; SO-A4,SO-A8-SO-A9]

The caller does not read request+8 in its retained next-request prefix. It rebuilds the record and calls `0x1004cf038 -> 0x100410c4c`, IA`0x704f`, then reaches the same imported malloc site with X0=74, X1=J+`0x120`=`0x6500115c40` and X2=20. The next record uses source pointer `0x1010130e0`; its path, allocation result and consumer remain unknown here. All48 paths preserve the original32 B field at J+`0x34` without access. No new Mach port/right, message-emission site, IOKit selector or filesystem call is established. [SO1-SO4; SO-A9-SO-A10]

## Assumption register and falsification probes

| Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- |
| SO-A1: Pinned source and canonical logical fixups apply | Source addresses, opcodes and imports | Check source SHA, every retained instruction, fixup slot and authenticated modifier; hardware PAC remains unobserved. |
| SO-A2: Four parent source states are conditional entries | All48 continuations and encoded directory | Exact GP/Q/NZCV/SP/byte/owner joins; retain the earlier separate constructor-byte premise without asserting a native epoch join. |
| SO-A3: Explicit pointer returns and valid disjoint owner spans apply | Allocation branches and accessible extents | Cross both ABI patterns, NULL/nonnull returns; add no initial definitions and map empty-owner backing without promoting bytes. |
| SO-A4: Initializer effects are opaque and free returns retire B | Post-API reads, failure cleanup and lifetime limits | Invalidate all200 L bytes for every status; verify no L-byte accesses, exact B retirement and no later B access; native destruction remains unknown. |
| SO-A5: Creator control and private output cell are the recovered interface | Lock pointer/status composition | Check address-keyed record packing, selected mode0xaed7, source L store and rebuilt all-u32 status/publication predicates. Installed SDK evidence does not prove native implementation equivalence. |
| SO-A6: Retained directory controls and length apply |20-byte copy and XOR98 | Check every source byte read/write, inherited21 B input and arbitrary-byte source equation; native external control is unknown. |
| SO-A7: Executed filename groups and header phase apply |12-byte basename and63/11 B split | Check source-image bytes, all three arbitrary-data quad equations, exact store order and complete74 B definition mask. |
| SO-A8: Local stores establish source order only | Raw pointer publication and file/path roles | Verify every field and publication after all writes; no native ownership, visibility, filesystem existence or kext delivery inferred. |
| SO-A9: Retained prefix bounds status use and cleanup | Unread status, preserved destination, next request | Check all source reads/calls and retired spans through next pending malloc; later status handling and L cleanup remain unknown. |
| SO-A10: Native imported operations are separate premises | Architectural/IPC limits | Retain exact allocation/init/free boundaries and no additional API output bytes; native filesystem/daemon-kext pairing requires independent evidence. |

## Reproducibility and bounded continuation

Checks logical SHA-256: `07a337c86186417bf07e4aaa78565bb7a75eac938128af0e42e3a097918a458d`. Audit logical SHA-256: `6ec2b37431f87db9631fdfa8f6725a7128e154b2c9d8719af1ad61024a677a4c`. [SO3-SO4,SO6]

The48 cases are the full product of four parents, two new ABI clobber patterns and six stated scenarios. They retain200 intervals,71112 source visits,9456 reads,2568 writes,2608 logical edges and88 internal calls. Independent replay checks2281984 scalar register values,2281984 vector register values,71312 flag states,50088 read B,16552 write B and2520 authenticated logical edges. It preserves152 exact API-return joins and48 ordinary joins. Eight successful cases check504 defined object bytes,88 undefined-gap bytes,272 pathname bytes and eight pointer publications. Thirty-two declared frees are checked separately. [SO3-SO4,SO6]

Eleven nonvacuous equations cover the allocation partition, aligned lock-record packing, object header, directory XOR98, the three basename groups, pointer publication, status store and two rebuilt all-u32 creator predicates. Source-equation solver limit is30 s/query. Field arithmetic uses exact u8/u32/u64 wrapping. Path construction takes O(D+F) time for D=20 directory bytes and F=12 filename bytes, with O(1) in-place auxiliary storage; independent comparison uses O(N) storage for N=74 B. Receipt/replay costs O(V*(register state+effects)+query DAG) time and O(receipts+largest interval+N) storage. Counts are exact for these paths, not native timing estimates. [SO1,SO3-SO6]

| Impact | Next evidence | Architectural consequence and limit |
| --- | --- | --- |
| High | Continue the pending J+0x120 path constructor | Recover the second state pathname and determine how the pair is consumed |
| High | Trace J+0x118 into actual filesystem calls and IPC construction | Establish open/create/update parameters and any daemon-kext data flow; current evidence stops at local construction |
| High | Recover native caller/constructor epoch linkage | Convert conditional source-compatible states into an execution-specific interface pairing |
| High | Follow L after initializer failure | Establish complete resource lifecycle; no native leak conclusion follows from this prefix |
| Medium | Recover consumers of B+8/+16/+24/+28 | Establish field semantics without treating zero values as handle or counter types |
| Medium | Recover pathname-input writers and serialization around publication | Establish native external control and concurrent visibility, which are currently unknown |

**QG1** passes: factual source/ABI analysis. **QG2** passes: SO-A1-SO-A10 register premises and probes. **QG3** passes for this state-path constructor/lock/cleanup increment; the full interface goal remains active. **QG4** passes: exact widths, extents, modular arithmetic, byte counts and complexity. **QG5** passes: target path versus native file use, source publication versus ownership, source-defined versus opaque bytes and requested versus actual cleanup remain distinct. **QG6** passes after independent source replay,11 nonvacuous equations, preserved-input and publication checks. **QG7** passes: bounded expansion covers the next path, filesystem/IPC consumers, native epoch joins, lock lifetime, field semantics and input/publication control.
