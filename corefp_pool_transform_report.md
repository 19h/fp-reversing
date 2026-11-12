# CoreFP pool-backed transform, shared context and nonzero retirement

Original `0x1af6b8` now returns completely through its larger body and both nonzero pool-retirement calls under an explicitly supplied private context. Seven complete controls and one original-context boundary control receive independent whole-source replay. The caller builds two 256-word workspaces, processes 16/32 B inputs, reads three u64 context words per block and retires the second allocation before the first. Both retirements restore the pool boundary and allocation counter; they invoke no native `free`.

The source context pointer is loaded from image+`0x1d45f60`, the same cell identified in the earlier [FPSD predicate report](fpsd1201_predicates_report.md). Its source initializer remains unknown. The original-context control stops before `0x1bafd8` with a zero base. The complete controls instead declare a separate private context buffer as an initial assumption. They establish conditional local behavior, not native initialization, algorithm identity, protected-content success or daemon/kext pairing. The full goal remains active.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_pool_transform.py), [checks archive](triage_evidence/corefp_pool_transform_checks.json.zst), [independent auditor](triage_evidence/audit_corefp_pool_transform.py), [audit archive](triage_evidence/corefp_pool_transform_audit.json.zst) and [publication verifier](triage_evidence/verify_corefp_pool_transform_publication.py) retain the evidence. The [caller report](corefp_pool_caller_report.md) and [allocator report](corefp_pool_allocator_report.md) define the preceding source contracts. CoreFP arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. Addresses are preferred-base-zero offsets; extents are bytes (B). The complete caller, allocator and retirement bodies total 59120 B. Complete body retention does not mean every branch executes.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PT1 | Pinned source, chained fixups, frozen readers and private PAC models identify the code. All source claims depend on them. | Compare three complete bodies, every executed instruction, reaching authenticated load, dependency and initial/final sparse RAM page. Preserve the three supplied reference inputs. |
| PT2 | The previous 48 B entry record, empty holder, selector 1, one 5000 B malloc result and stack geometry apply. Local caller/lifetime results depend on these premises. | Independently reconstruct all eight initial CPU/RAM states; check source-produced child records, both requested extents, exact stack/return preservation and volatile clobber. Native admission remains unknown. |
| PT3 | Private context backing and its offset controls are explicit initial fixtures. Complete-return and output results depend on them. | Preserve the original zero-base boundary control; test ramp, zero and one-byte-changed context, offsets 0/8/16, and unchanged context memory. Establish an original initializer before claiming native readiness. |
| PT4 | Seven-round reduction applies only to the retained unrolled component. Component semantics depend on its source bindings. | Reconstruct all seven immediate constants; compare all component inputs/results and 56 round evaluations. Prove the arbitrary u64 round inverse. The larger transform remains unidentified. |
| PT5 | Retirement receives the two same-epoch private allocation results. Pool restoration depends on that ownership premise and the sequential token model. | Verify reverse allocation order, record epochs, both 416 B fill effects, complete arena transitions and counter/boundary restoration. Native concurrency, foreign-object retirement and allocator interoperability remain unknown. |
| PT6 | Shared global identity is local data-flow evidence. Architectural implications depend on that scope. | Compare the exact base/offset cells with prior FPSD consumers; require a source initializer and actual handoff before assigning native ownership, IPC identity or cross-level pairing. |

## Continuous control and workspace use [PT1-PT3,PT5]

```text
original entry 0x1af6b8, operation 0x7f48
  -> periodic XOR prefix and separate 16 B stack preparation
  -> length gate -> two operation-0x2b9b allocation calls
  -> one 5000 B backing, interior requests 1027 B / 1031 B
  -> 0x1b0270: larger body
       -> two 256-word workspace writes
       -> per-block processing and three context-word reads
       -> final output byte stores
  -> 0x1b0168: retire SECOND allocation through 0x5c87d4
  -> 0x1b01e8: retire FIRST allocation through 0x5c87d4
  -> 0x1b0234: raw marker 0xba1df9db -> original return
```

All controls start at the original entry. No PC, child record, parent stack or source-produced pointer is substituted. Private context is installed before execution. The original-context control traverses the first part of the larger body, then stops before the unresolved context read. No read at address zero occurs in the delivered profiles.

| Workspace / source store | Source-produced pointer | Established writes |
| --- | --- | --- |
| First allocation, `0x1b6a38` | A+`0xf60` = `0x64002f60` | 256 u32 stores, exactly 1024 B, within 1027 B request |
| Second allocation, `0x1b6a50` | A+`0xb34` = `0x64002b34` | 256 u32 stores, exactly 1024 B, within 1031 B request |
| Backing A | `0x64002000` | One declared 5000 B malloc result inside an 8192 B private mapping |

Every profile writes each workspace word exactly once at the two source sites. This establishes the workspace extents and local consumption path; it does not identify their complete mathematical interpretation. The auditor independently replays every subsequent source read/write. A complete reduced oracle for the whole transform is not claimed.

## Shared context addressing [PT1,PT3,PT6]

| Source / fixup | Local role |
| --- | --- |
| Row `0x1d09288` -> image+`0x1d45f60` | Pointer cell; `0x1bafd0` loads its u64 value into X19 |
| Row `0x1d0fea0` -> image+`0x1d44440` | U32 context-offset input, read at `0x1baf60` |
| `0x1bafd8` | First u64 read at X19 plus zero-extended W8 |
| `0x1bb2b8` | Second u64 read through the same X19 |
| `0x1bb50c` | Third u64 read through the same X19 |
| Earlier FPSD reads `0x8ea398`, `0x8ea3a0` | Previously established consumers of the same pointer/offset cells |

Let U be the u32 offset cell. At each recorded phase W is the corresponding source intermediate. All operations below have u32 width:

```text
first_index  = U AND 0xfffffff8 AND (W XOR 0xf694e362)
second_index = U AND ((W AND 0xfffffff8) XOR 0xebc72a90)
third_index  = U AND ((W AND 0xfffffff8) XOR 0xfa751e48)
address      = context_base + zero_extend(index), modulo 2^64
```

The first expression is universally reduced from the original AND/XOR construction. A second universal obligation establishes that all three indices are 8 B aligned and contain no bits outside U. It does not establish that arbitrary U fits a native allocation. The effective pointer rows and phase inputs are checked for the finite profiles; no new all-input resolver proof or writer census is claimed.

| Private context control | Read offsets, first / second / third | Output for the retained 16 B input |
| --- | --- | --- |
| Ramp bytes, U=0 | 0 / 0 / 0 | `732780382ca3157581b95dc50e78053a` |
| Zero bytes, U=0 | 0 / 0 / 0 | `b0f5fd31655114b086dfab736308dedd` |
| Ramp with byte 0 XOR `0x80`, U=0 | 0 / 0 / 0 | `800f342a3c4a709ec14f244d777414e4` |
| Ramp bytes, U=8 | 0 / 8 / 0 | `732780382ca3157506405e841377783e` |
| Ramp bytes, U=16 | 0 / 0 / 16 | `732780382ca3157581b95dc50e78053a` |

Ramp means byte j equals j modulo 256 in a 4096 B private buffer at `0x64004000`. Its address is separate from the backing arena, input, output and stack. All context reads are 8 B and all context bytes remain unchanged. The U=16 control changes the third read but retains the same output in this finite comparison; that equality is not a proof of general independence. Context-content changes produce distinct output, and the volatile-clobber control matches the baseline output.

The 32 B control executes six context reads and returns `732780382ca3157581b95dc50e78053ac5b7fff067cc57fe31ab3e8518dc03f3`. This vector and the 16 B vectors are original-source replay results. They are not native vectors or a complete independent specification of the unknown transform.

## Seven-round 64-bit ARX component [PT1,PT3,PT4]

The unrolled section beginning at `0x1bafd8` reduces to seven rounds with u64 state (a,b):

```text
a_next = (ROR64(a,8) + b) XOR K, modulo 2^64
b_next = ROL64(b,3) XOR a_next
```

The recorded first input is already rotated by the preceding source `EXTR`; the oracle accounts for that phase rather than assuming a new block-input convention. It checks the source state again at `0x1bb0dc`, including the subsequent unkeyed addition. The seven immediate constants are reconstructed directly from original MOV/MOVK instructions:

| Constant source | K, u64 |
| --- | --- |
| `0x1bafe0` | `0x91c8addf2d0476cf` |
| `0x1bb000` | `0xced7f5beeac60162` |
| `0x1bb020` | `0x9ba725ad6478ec0e` |
| `0x1bb040` | `0x69ad135e9d6c5483` |
| `0x1bb060` | `0x2c093d6838485baf` |
| `0x1bb080` | `0x8023744e17595bd3` |
| `0x1bb0a0` | `0x2a187c9d9de4a9c0` |

The independent oracle evaluates 56 rounds across eight executed block instances. A universal inverse obligation checks `b=ROR64(b_next XOR a_next,3)` and `a=ROL64((a_next XOR K)-b,8)` for arbitrary u64 a,b,K. This proves the local round's invertibility. It does not establish a standard cipher identity, complete key schedule, complete transform equivalence or secret-key recovery.

## Same-epoch retirement and pool restoration [PT1,PT2,PT5]

The complete body reuses the cleanup record at `0x62017f78` under operation `0x88cd`. The two previously retained NULL calls could not discriminate pointer order. The new nonzero calls establish the following order and transitions:

| Call / return | Retired pointer | Holder+`0x28` decrement | Free-boundary offset after return |
| --- | --- | --- | --- |
| `0x1b0168` / `0x1b016c` | Second allocation, A+`0xb34` | 1068 | 3912 |
| `0x1b01e8` / `0x1b01ec` | First allocation, A+`0xf60` | 1064 | 4976 |

The two allocation increments sum to 2132; the two retirements subtract the same total. With C=`0x2fecaf1f3ee407fa`, header A+8 becomes C+3912 and then C+4976. Each newly exposed endpoint receives the corresponding boundary value. Both holder endpoints remain A, and the backing node's reciprocal links remain intact. No second backing allocation and no `_free` import occurs.

Each retirement also executes two bounded byte-fill loops: 250 B at `0x5c8ce8` and 166 B at `0x5c9264`. At the retained caller stack geometry, their source seeds are respectively `0x62017aa0` and `0x62017a90`. Each stores `((seed+j) XOR 0xba)*(seed+j+17) mod 256` in descending destination order; the first loop's source increment is independently checked as 1. The auditor constructs these byte effects and boundary changes independently and compares the complete 8192 B arena after each call. The total is 832 fill bytes per complete profile. This is a partial fill contract, not full-payload erasure.

The original pair cell retains both interior values after retirement. Restored free metadata does not imply that every workspace byte is restored or that a later consumer may reuse those values. No later native consumer or ownership transfer is established. SP and callee-saved registers restore at all seven complete outer returns. The record's raw marker becomes `0xba1df9db`; the other entry-record bytes and diagnostic OUT cell remain unchanged. This raw value is not assigned a public error/status enumeration.

## Architectural context, validation and continuation

The shared pointer/offset cells connect this local transform to an earlier context consumer in the FPSD path. They do not connect the two operations temporally or establish a daemon/kext exchange. No retained path invokes Mach send/receive, port allocation, MIG reply-port handling or descriptor transfer. Incoming/outgoing native port identities and emission sites gain no new evidence here.

A read-only MCP xref request for the context cells and pointer row returned that a matching authenticated IDA Assist bridge worker was unavailable. No current IDB byte corroboration, writer result or memory retrieval is claimed, and no IDB is mutated. Original file/fixup evidence and independently replayed receipts support this increment.

Fresh independent checks cover eight profiles, 629751 original instruction visits, 82153 reads, 53068 writes, 27212 PAC models, 38 API/sequential-CASAL models, 212 state points, eight malloc attempts and 30 child entries. Seven profiles return; the original-context control stops before its first unresolved read. The auditor reconstructs all initial CPU frames and 4333568 B each of initial/final sparse RAM, verifies 180224 B of compact arena oracles and checks 5824 cleanup-fill bytes. Three complete source bodies total 59120 B.

Three new universal obligations and nine freshly rechecked frozen caller/allocator obligations pass as UNSAT. The fresh source checks also retain the earlier 5632 original-bank input cases and syntax-only SDK assertions. The 56-round oracle covers only the reduced component; complete transform results are checked by independent original-byte replay, not a complete reduced algorithm oracle. Conservative replay time/space is `O(C*(B+P*F+V*J+R))`, bounded at 150000 visits/profile; bank work is `O(256*K)`, each arena oracle is `O(8192)` and each seven-round component oracle is `O(7)`. SMT has a separate 30 s/query limit. No native target/API/IPC executes.

| Impact | Next investigation | Completion / falsification condition |
| --- | --- | --- |
| High | Establish writers and lifecycle of image+`0x1d45f60` and image+`0x1d44440`. | Recover source initialization, allocation extent, lifetime and selected offset domain. Private context fixtures do not establish native readiness. |
| High | Recover the whole transform's compact mathematical structure. | Independently specify both 256-word workspaces, table stages, every block input/output step and all remaining ARX sections; compare original-source vectors. The seven-round component alone is insufficient. |
| High | Locate the upstream 48 B record producer and native selector/holder initialization. | Require original same-epoch argument stores and a valid admission path; output markers alone do not establish exposure or accepted processing. |
| Medium | Compare retained cleanup behavior with other valid pool states. | Establish list topology, neighbor allocation states and token epochs before generalizing coalescence beyond these two paired blocks. |
| Medium | Resolve the preparation-root relationship to this pool. | Match object layouts and original handoffs; backing-node and preparation-consumer identities remain distinct. |
| Low | Join local context use to daemon/MIG evidence. | Require a source handoff and matched message epoch before assigning transported content or a port/right identity. |

- **QG1**: No normative premise is required; claims concern source behavior and evidence bounds.
- **QG2**: PT1-PT6 state assumptions, dependent results and falsification probes.
- **QG3**: Caller entry, buffer production/consumption, context addressing, local ARX structure, nonzero retirement, control/environmental context and Mach limits are covered.
- **QG4**: U32/u64 operations, rotations, B extents, alignment, stack seeds, workspace bounds and counter arithmetic are explicit and independently checked.
- **QG5**: Initial fixtures, source-produced records, complete returns and the zero-context frontier remain distinct. Cleanup order now has nonzero evidence; complete algorithm and native readiness remain unknown.
- **QG6**: Pinned original bytes/fixups, independent CPU/RAM replay, compact arena/ARX oracles, solver queries and SDK declarations provide provenance. Current IDA availability is reported separately.
- **QG7**: Impact-ranked continuation preserves unresolved initialization, mathematical structure, admission, lifetime and cross-level pairing. The full investigation remains active.
