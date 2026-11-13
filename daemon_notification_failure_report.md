# Notification-failure cleanup, encoded record headers and caller result

The six nonzero registration/baseline-check routes now continue through the original helper cleanup and return to the original caller consumer. In the retained conditional contexts, each route clears the saved result, reaches helper return value zero and selects caller target `0x1006cdaf8`. Separately declared nonempty-record controls recover four pending `free` sites and exact 16 B header rewrites. These source results do not join the missing provider epoch, establish native notification success, or prove native object ownership. [NF1-NF8]

```text
explicit clock-success entry -> original caller -> constant -2 leaf
  -> original helper prefix and encoded-null initializers
                  |
          unproved provider/control/lifetime gap
                  v
separate registration cut + explicit API return/output premises
  nonzero registration/baseline status
    -> W28 = 0; cleanup phase W25 = 0x1f8
    -> 0x100e24d08
       record A absent -> skip A
       record A present -> optional free(payload A)
                           rewrite header A -> free(record A)
       record B absent -> skip B
       record B present -> optional free(payload B)
                           rewrite header B -> free(record B)
    -> original canary check / frame restoration / RETAB
    -> original caller consumer: result 0 -> W28 = 0x8b3dc651
    -> STOP before target 0x1006cdaf8

Imports stop before execution; each continuation needs a declared return.
Nonempty cleanup records are additional entry premises.
```

## Assumption register

| ID | Assumption and dependent conclusions | Stress test / falsification probe |
| --- | --- | --- |
| NF-A1 | The pinned original daemon and parent receipts identify the source build. All addresses/source claims depend on that identity. | Rehash source/dependencies; compare original opcodes, source fixup words and all retained query results. Native daemon/provider identity remains unknown. |
| NF-A2 | Clock-success begins at its existing explicit cut; five compatible frame roots and live caller scalars are premises. Its source prefix and the post-provider registration cut remain unjoined. | Execute both internal calls and the helper prefix without replacement of their registers/PC; verify actual helper-entry arguments, saved frame and return consumer. Require the missing provider/output/lifetime epoch before joining the two entries. |
| NF-A3 | Retained failure cases preserve the original initialized null sentinels across the cut. Nonempty controls instead declare distinct valid 16 B records and payload pointers. | Cover all six failures and all nine record-state pairs, with two SP placements and controller pairs. Require original producers and complete extents before assigning allocation format, pointer ownership or native aliasing behavior. |
| NF-A4 | Imported notification statuses/outputs and normal void free returns are explicit interval premises. Native implementations do not execute. | Vary caller-saved/NZCV fixtures, backing patterns and baseline outputs; independently lift every interval and check all arguments. Preserve X18 and callee-saved state at the declared API boundary. |
| NF-A5 | Private backing remains available after a modeled free return only for analysis. Source retirement is not native allocator state. | Reject every subsequent source read/write overlapping the retired 16 B record span. Do not infer actual deallocation, allocator metadata, payload extent, alias safety or a native use-after-free result. |
| NF-A6 | Source constants, fixed cleanup phases and bank/table epochs compose the local pointer/status proofs. Hardware PAC and canary-failure behavior are not modeled. | Prove complete u64 bias/zero predicates, exact header effects and result forwarding; check 31 original intervening instructions do not write X15 or SP between the linked sentinel slices. Independently compare saved registers and source canary behavior under the declared guard fixture. |
| NF-A7 | Current arm64e SDK declarations compare the pending free ABI; original SDK/runtime pairing remains unknown. | Compile `void free(void *)` and 8 B pointer assertions against a hashed relative header. An arbitrary X0 fixture after void return is not a status. |
| NF-A8 | Publication covers the explicit owned increment; broader interface completion remains unproved. | Verify receipts, exact manifest delta, original-input preservation, compressed round trips, raw/typed/decoded path hygiene and final remote hash. |

## Actual caller prefix and conditional failure join

The original instructions starting at `0x1007019b0` execute the constant -2 leaf and call helper `0x100e1e5ec`. The helper receives the four existing frame output addresses with widths 8, 4, 8, 4 B. That prefix stops at `0x100e1e97c`; the later registration entry remains the separate cut at `0x100e1fd98` from the [registration report](daemon_notification_registration_report.md). No original provider outputs or uninterrupted path across that gap are supplied. [NF1-NF5]

All six imported-return continuations contain a source result reset and reach the common failure continuation with X28=0 and W25=`0x1f8`. A source query covers arbitrary u32 imported statuses, arbitrary caller-saved scalar contents and arbitrary prior X28, retaining the source-derived callee-saved state of those call sites. Together with the previous six zero-only gates, this establishes the exact nonzero-status route and its reset result within these contexts. It does not assign a business error meaning to the notification statuses. [NF1-NF5]

The original prefix clears all four caller output cells. The post-provider cut does not supply provider writes to those cells, and the retained later source intervals perform no additional stores to them. Thus their retained zeros are consequences of the declared cut, not recovered native provider outputs or proof that actual failures clear completed outputs. [NF2-NF5]

## Encoded null sentinels and accessed record headers

The source initializes two encoded pointer cells in its helper frame F. Their biases are distinct. All additions/subtractions in this section are modulo 2^64. [NF2-NF5]

| Cleanup record | Frame cell | Original null initializer | Decode |
| --- | --- | --- | --- |
| A | F+`0x160` | `0x0e5d2a6f87a8427c`, store `0x100e1e72c` | raw A = encoded A - `0x0e5d2a6f87a8427c` |
| B | F+`0x1c0` | `0x7dd5cf10709e5799`, second element of STP at `0x100e1e728` | raw B = encoded B - `0x7dd5cf10709e5799` |

Each sentinel comparison is exactly equivalent to the decoded pointer being zero. Nonzero controls declare distinct raw record addresses with an accessed extent of 16 B, consisting of one u64 at +0 and two u32 cells at +8/+12. Only the +0 pointer is read by this cleanup; the two u32 cells are overwritten with fixed marker values. Complete record size, allocator extent, marker meanings and payload extent remain unknown. [NF2-NF5]

| Source predicate | Zero target | Nonzero target |
| --- | --- | --- |
| Decoded A pointer | `0x100e24ef4`, skip A | `0x100e24d60`, inspect A |
| A+0 payload pointer | `0x100e24e3c`, rewrite A | `0x100e24dcc`, prepare payload free |
| Decoded B pointer | `0x100e25080`, epilogue | `0x100e24f5c`, inspect B |
| B+0 payload pointer | `0x100e24ff4`, rewrite B | `0x100e24f94`, prepare payload free |

The four source predicates are proved for arbitrary u64 values under the recovered local cleanup phases. They are stronger than the concrete null/non-null controls, while native validity of a decoded pointer remains an additional premise. [NF2-NF5]

## Pending frees and exact header rewrites

Each non-null payload is offered to `free` before its containing record header is rewritten. A present record is offered to a second `free` even when its payload was null. Four distinct original bank rules all select import slot `0x1010b1578`, `libSystem/_free`, IA diversity `0x6463`. All 256 selector inputs are checked for each rule. [NF2-NF6]

| Call site | X0 argument | Condition |
| --- | --- | --- |
| `0x100e24e28` | u64 payload pointer loaded from A+0 | A present and payload nonzero |
| `0x100e24eec` | decoded raw A record address | A present, after its header rewrite |
| `0x100e24fdc` | u64 payload pointer loaded from B+0 | B present and payload nonzero |
| `0x100e2507c` | decoded raw B record address | B present, after its header rewrite |

The source performs these exact writes before requesting record retirement. The values are reported as markers; no length, capacity, type or status meaning is assigned. [NF2-NF5]

| Record | Offset / width | Value | Original store |
| --- | --- | --- | --- |
| A | +0 / 8 B | zero | `0x100e24e68` |
| A | +8 / 4 B | `0x374e946a` | `0x100e24e88` |
| A | +12 / 4 B | zero | `0x100e24ea0` |
| B | +0 / 8 B | zero | `0x100e24ff4` |
| B | +8 / 4 B | `0x1d6d1efe` | `0x100e25014` |
| B | +12 / 4 B | `0x655b53a7` | `0x100e2502c` |

The current arm64e SDK compile confirms `void free(void *)` and 8 B pointers. A modeled free return supplies arbitrary caller-saved register/NZCV changes and an unspecified full-u64 X0 fixture; X0 is not a free status. Private backing remains available to the analyser, but no later retained source read/write overlaps the 16 B record span after its record-free return premise. This proves a bounded source access property, not native allocation/deallocation, payload ownership, or an aliasing guarantee. [NF3-NF6]

Across the retained suffix there is no notification cancellation, readiness store or additional token-cell store. Token contents reflect only the preceding declared successful registration outputs. Complete retry behavior and process-lifetime cleanup remain unknown. [NF1-NF5]

## Helper epilogue and original caller consumer

The original epilogue checks the declared canary, copies the full saved X28 result to X0, restores its 1,184 B frame and X19..X30, then executes RETAB to `0x100701a7c`. The prefix recorded the actual internal helper entry, allowing independent comparison of every restored saved register with its entry value. Hardware return authentication and the canary-failure branch remain unexecuted. [NF2-NF5]

All 84 cases return X0=0 because the six imported-return routes clear X28 and the retained cleanup preserves it until result forwarding. The later restoration of caller X28 is a separate epoch: it restores a bank pointer, not the result just copied to X0. The actual caller then computes the existing u32 status transform and dispatches through slot `0x101076e40`, index `0x79ea`, IA diversity `0x4113`, to stopped target `0x1006cdaf8`. Its new W28 is `0x8b3dc651`. No meaning beyond the source zero/nonzero gate is assigned to that target. [NF1-NF5]

For arbitrary u32 `r`, all operations modulo 2^32:

```text
d = r - ((r << 1) & 0x167b8ca2)
caller W28 = d + 0x8b3dc651
d == 0  <=>  r == 0
```

The general nonzero selector remains index `0x7a10`, target `0x100709868`; it is source-classified rather than selected by these zero-return cases. The current source result establishes local handling of notification failure under the stated cuts. It does not establish completed provider outputs, a native error response, or a daemon-kext transaction. [NF1-NF5]

## Mach and architectural scope

This increment establishes no incoming/outgoing Mach port, right operation or message-emission site. Cleanup calls resolve to `free`, and the caller successor is an internal source address. Notification registration/check imports remain stopped; their explicit returns do not establish transport completion or service/right identity. The [registration report](daemon_notification_registration_report.md) and [transport report](notify_ipc_report.md) retain their separate name, implementation-version and native-pairing limits. [NF1-NF8]

The local architectural result is a notification-return/result boundary: a nonzero notification status selects common cleanup while a separate saved helper result is cleared to zero, then the caller consumes that helper result. The notification status and helper result must therefore remain separate fields/epochs in further analysis. Native provider errors, output ownership and complete daemon-kext response semantics remain unknown. [NF1-NF5]

## Provenance and reproducibility

| ID | Evidence | Scope |
| --- | --- | --- |
| NF1 | [Notification registration](daemon_notification_registration_report.md), [four-output helper](daemon_environment_outputs_report.md), pinned parent receipts | Source imports, token roots, six status gates and caller ABI |
| NF2 | [Failure extractor](triage_evidence/recover_daemon_notification_failure.py), original `source_regions`, `source_pool`, `source_fixups`, `bank_rules` | Exact opcodes, encoded pointers, free arguments, header stores and caller continuation |
| NF3 | [Checks archive](triage_evidence/daemon_notification_failure_checks.json.zst) | 84 cases, 612 intervals, source journals, all explicit entry/return premises and 12 source queries |
| NF4 | [Independent auditor](triage_evidence/audit_daemon_notification_failure.py) | Independent byte-addressed lift, saved-register/effect/argument checks and post-retirement access checks |
| NF5 | [Audit archive](triage_evidence/daemon_notification_failure_audit.json.zst) | 1,224 independent interval lifts, alternate controls and 31-instruction sentinel nonclobber check |
| NF6 | NF5 `SDK_checks` | Current arm64e void-free prototype, pointer width and relative header hash |
| NF7 | [Publication verifier](triage_evidence/verify_daemon_notification_failure_publication.py) | Fresh receipt/source pins, source queries, parent status-gate queries and exact publication delta |
| NF8 | [Manifest](triage_evidence/interface_manifest.json.zst) and NF7 | Original-input preservation, archive round trips and owned-content path hygiene |

Original daemon thin SHA-256 is `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Dependency and implementation hashes are embedded in NF3/NF5. No analyst-machine paths are retained.

The 48 retained failure cases cover 6 failing notification sites x 2 SP placements x 2 controller pairs x 2 not-ready flag values. The 36 additional cleanup controls cover 3 states for A x 3 states for B x 2 placements x 2 controller pairs, using first-registration failure as their common-entry context. States are absent sentinel, present record with null payload, and present record with non-null payload. They do not enumerate native aliasing or ownership states. [NF3-NF5]

| Validation extent | Verified count |
| --- | ---: |
| Source cases / intervals | 84 / 612 |
| Original source visits | 45,972 |
| CPU reads / writes / logical edges | 11,952 / 4,764 / 1,008 |
| Notification-return / void-free-return premises | 204 / 72 |
| Unique original instructions / opcode extent | 848 / 3,392 B |
| Retained fixup records / classified alternate caller slot | 50 / 1 |
| Free bank rules / selector inputs checked | 4 / 1,024 |
| New nonvacuous source queries, UNSAT | 12 |
| Parent status-gate queries rechecked, UNSAT | 6 |
| Independent interval lifts / visits | 1,224 / 91,944 |
| Register values / NZCV values checked | 2,981,376 / 93,168 |
| Read bytes / write bytes checked | 144,096 B / 70,752 B |
| Original authenticated edges checked | 1,680 |
| Accessed-header rewrites / payload-free requests | 48 / 24 |
| Sentinel linking instructions checked for nonclobber | 31 |
| Current SDK ABI compilation | exit 0 |

The source queries cover original sentinel constant/store slices, four pointer predicates, two full-u64 bias decodes, two exact header rewrites, full-u64 result forwarding, all six import-result resets/shared phases and the caller's complete u32 status transform. The query count is 12 because each listed combined obligation is retained as one query. Source opcodes and original fixup fields are separately checked. [NF2-NF7]

For C cases, V visits, E byte effects, S retained source/bank bytes and Q queries, extraction uses O(C(V+E)+S+Q) work and journal storage excluding solver-internal cost. The audit uses O(CV(R+B)+S+Q) work/storage for R register/flag checks and B byte effects per visit. Each query has a 30 s limit. Both physical backing patterns are independently lifted; baseline outputs and caller-saved/void-X0 fixtures vary while source control, stores, calls, helper return and caller target remain stable. Archive logical bytes are round-trip checked after `zstd --ultra -22 -q -T1`. [NF2-NF8]

## Bounded continuation

| Impact | Remaining question | Falsification / next evidence |
| --- | --- | --- |
| High | What real provider state reaches registration and cleanup? | Recover an uninterrupted path across the provider call and output writers. Reconcile its encoded record fields with these source null initializers and conditional cleanup records before asserting a native lifecycle. |
| High | What follows caller target `0x1006cdaf8`? | Carry the actual restored caller frame and encoded status forward; recover subsequent output/error consumers before assigning an external response meaning. |
| High | How are the raw records allocated, filled and published? | Trace original stores to F+`0x160`/F+`0x1c0`, their allocations and encoded biases. Establish complete record and payload extents and owners. |
| Medium | How does a later retry handle partially registered tokens? | Join caller re-entry and readiness epochs; this retained suffix has no cancellation or readiness/token reset but native retry/retirement is not established. |
| Medium | Do the two record formats share a deeper representation? | Recover marker producers/consumers across other original callers; matching 16 B accessed layouts alone does not establish a common type. |
| Low | What alternate canary/PAC or pointer-alias contexts exist? | Identify original valid callers/epochs before expanding the declared disjoint-record and logical-return premises. No native failure or memory-safety claim follows from these controls. |

## Quality gates

- **QG1**: Technical source, ABI and provenance claims require no normative premise.
- **QG2**: NF-A1..NF-A8 enumerate assumptions, dependent results and falsification probes.
- **QG3**: Failure/control flow, encoded data, cleanup ABI, saved frame, caller status, native unknowns and port/emission limits are covered.
- **QG4**: u32/u64 operations, modulo arithmetic, byte extents, case products and counts are explicit and reproducible.
- **QG5**: Separate provider cuts, declared nonempty records/free returns, changed register epochs and unknown native ownership remain distinct.
- **QG6**: Original bytes/fixups, source equations, independent interval effects, SDK assertions, dependency pins and publication delta are verified.
- **QG7**: Continuations are bounded and impact-ranked; the full interface investigation remains active.
