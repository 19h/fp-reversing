# Daemon ADID notification names, registration gates and exit callback

Failure continuation: The [cleanup and caller-return report](daemon_notification_failure_report.md) extends the former 0x100e24d08 frontier. It recovers two encoded null sentinels, optional payload/record frees, header marker writes, actual frame restoration and zero helper result in retained failure contexts. Registration-to-provider/lifetime continuity, native allocation/notification success and complete response semantics remain unknown.

The daemon's three cached notification-token cells now have source-level registration names: `com.apple.adid.midchangedV1`, `com.apple.adid.midchangedV1.5`, and `com.apple.adid.midchangedV3`. Original registration, baseline-check, readiness-publication and exit-callback sites are recovered. This identifies the namespace behind the [four-output helper's checks](daemon_environment_outputs_report.md). The root prefix, later registration cut and exit callback remain separate entries; native registration, delivery and daemon-kext transaction identity are unknown. [NR1-NR8]

```text
separate original root prefix -> source-compatible token/flag/bank roots
                                      |
                 unproved provider/control/lifetime gap
                                      v
post-provider cut 0x100e1fd98: ready byte bit 0?
  1 -> skip registration/baselines/atexit -> STOP before clock call
  0 -> register V1 -> register V1.5 -> register V3
       each status != 0 -> STOP before common failure continuation
       baseline check V3 -> check V1.5 -> check V1
       each status != 0 -> STOP before common failure continuation
       atexit(callback=0x100df2f60)
       ignore atexit result -> ready byte := 1 -> STOP before clock call

separate exit-callback entry 0x100df2f60
  cancel V1 -> cancel V1.5 -> restore frame and saved registers
  STOP before return-address guard
  source-classified guard -> requested cancellation tail call for V3

Arrows across imports require explicit return/output premises.
No imported implementation or native notification executes.
```

## Assumption register

| ID | Assumption and dependent claims | Stress test / falsification probe |
| --- | --- | --- |
| NR-A1 | The pinned original daemon and parent receipts identify this source build. All daemon addresses depend on that identity. | Rehash the original file and dependencies; compare every retained opcode and original fixup word. Native task/provider identity remains unknown. |
| NR-A2 | The original root prefix establishes compatible frame roots; registration begins at a separate post-provider cut. Registration-path conclusions depend on this cut. | Execute the prefix separately; check the original token/flag pointer stores. Do not join the entries until the missing provider result, output initialization and uninterrupted control/lifetime path are established. |
| NR-A3 | Controller/token/flag values and one pending-clock pointer are declared private fixtures. Callback entry is separate from native exit. | Vary two SP placements, two controller pairs and flag values 0..3; check all 256 selector inputs for 20 bank rules. Require a native registration/exit epoch before asserting lifecycle pairing. |
| NR-A4 | Each import stops before its instruction. Listed u32 statuses, token/check outputs and ABI register/NZCV changes are explicit continuation premises. | Check exact pre-call arguments; independently lift every interval; vary caller-saved clobbers and outputs. Preserve X18 and callee-saved registers across the modeled boundary. No implementation or actual API success is inferred. |
| NR-A5 | Failure output preservation is a chosen fixture, not an API guarantee. Failure-path conclusions end at `0x100e24d08`. | Prove all six status gates for arbitrary u32 returns and caller-saved scalars. Inspect later common continuation before claiming complete cleanup, returned status or retry behavior. |
| NR-A6 | Logical authenticated targets and normalized callback pointers describe source edges, not hardware PAC results. | Decode 44 original fixup records and check 816 independently lifted authenticated edges. Stop before the exit tail guard; prove its bit predicate separately. |
| NR-A7 | Current SDK prototypes are ABI comparisons; archived ADID names/class proofs are historical reference evidence. | Compile current arm64e declarations, pin retained reference hashes and recheck the historical class query. The installed provider fails the historical image pin; current provider/class/transport pairing is not asserted. |
| NR-A8 | Publication covers the explicit owned delta and keeps the larger goal active. | Verify receipts, manifest entries, original inputs, archives and raw/typed/decoded-payload path hygiene; compare the final remote commit. |

## Exact name, token and consumer mappings

All addresses below are unslid original daemon addresses. The registration names are NUL-terminated source strings selected through the original two-bank rules. Registration supplies a pointer to one 4 B token cell; later check and cancellation sites load that same cell. A token is an int32 notification handle, not a Mach port name. [NR1-NR6]

| Original name | Name address | Token cell | Registration call | Baseline check | Existing argument-dependent check |
| --- | --- | --- | --- | --- | --- |
| `com.apple.adid.midchangedV1` | `0x101032fa3` | `0x1010ca2c0` | `0x100e1fe88` | `0x100e20270` | `0x100e1f3e4` |
| `com.apple.adid.midchangedV1.5` | `0x101032f85` | `0x1010ca31c` | `0x100e1ff5c` | `0x100e201c0` | `0x100e1f498` |
| `com.apple.adid.midchangedV3` | `0x101032fbf` | `0x1010ca324` | `0x100e20054` | `0x100e200f4` | `0x100e1f2d8` |

The three registration decoders select index `0xb30` in dispatch base `0x1010abb60`, import slot `0x1010b14e0`, `libSystem/_notify_register_check`, IA diversity `0x6463`. The names come from slots `0x1010b1840` minus 12 B, `0x1010b18a0` unchanged, and `0x1010b17e0` minus 4 B. All name biases are original instructions. A modifier match alone is not used as an import identity. [NR2-NR5]

Current SDK declarations compare as:

```c
uint32_t notify_register_check(const char *name, int *out_token);
uint32_t notify_check(int token, int *check);
uint32_t notify_cancel(int token);
int atexit(void (*function)(void));
```

The compile assertions establish 4 B int/u32 and 8 B pointers for the current arm64e target. They do not establish the original SDK or native libnotify build. [NR6]

The original helper prefix stores the token roots at F+`0x60`, F+`0x58`, F+`0x68`, and the readiness-byte pointer at F+`0x80`, where F is helper SP after its reservation. Those are original source effects. The later cut reuses the compatible roots while leaving its provider/output/lifetime predecessor unproved. Fixture token writes `0x7101`, `0x7102`, `0x7103` represent successful registration outputs only within the declared continuations. Initial token fixtures `0x7001`..`0x7003` are not native observations. [NR1-NR5]

Combining these source roots with the previous helper's argument predicates assigns V3 to the u64 two's-complement values -8, -6, -5, -4, -3, -2; V1.5 to -1; and V1 to other nonzero values. The original clock-success leaf supplies -2 and therefore selects the V3 token cell. This establishes a source namespace/class association, not the business origin of the incoming scalar or a native token value. [NR1-NR5, NR7]

## Registration, baseline and readiness control

The source at `0x100e1fd98` tests only bit 0 of the byte at `0x1010ca320`. Bit 0 set selects dispatch index `0xd3` and the already-ready continuation; bit 0 clear selects `0xdf` and registration. A source query covers every u8 flag. The four concrete controls distinguish values 0/2 and 1/3. [NR2-NR5]

Registrations occur in V1, V1.5, V3 order. Their status gates accept only W0=0. Baseline checks then occur in reverse order, V3, V1.5, V1, also requiring W0=0. All six nonzero routes select original common continuation `0x100e24d08`; the retained intervals stop before that continuation. Source obligations quantify every u32 status and arbitrary caller-saved scalar register contents, while retaining the source-derived callee-saved state of this cut. [NR2-NR5]

| Completed call | Zero-status target | Nonzero-status target |
| --- | --- | --- |
| Register V1, `0x100e1fe88` | `0x100e1fec0` | `0x100e24d08` |
| Register V1.5, `0x100e1ff5c` | `0x100e1ff8c` | `0x100e24d08` |
| Register V3, `0x100e20054` | `0x100e20084` | `0x100e24d08` |
| Baseline V3, `0x100e200f4` | `0x100e20128` | `0x100e24d08` |
| Baseline V1.5, `0x100e201c0` | `0x100e201f4` | `0x100e24d08` |
| Baseline V1, `0x100e20270` | `0x100e202a0` | `0x100e24d08` |

Each baseline check resolves slot `0x1010b16a8`, IA diversity `0x89e0`. The changed-result destinations are F+`0x154` for V3, F+`0x1dc` for V1.5, and F+`0x1d4` for V1. The registration-cut cases explicitly supply baseline outputs at successful modeled returns; their initialization before this cut and successful native writes are not inferred. Their returned changed values are not read by the retained registration suffix. Opposite zero/all-ones changed-result fixtures preserve source control and stores. [NR2-NR5]

After all six zero statuses, `0x100e20318` requests `atexit(0x100df2f60)`, import slot `0x1010b16b0`, IA diversity `0x965f`. The callback pointer is constructed by the original ADRP/ADD and PACIZA sequence; only its normalized source address is represented here. The suffix does not inspect the atexit result. `0x100e20328` stores byte `1` to `0x1010ca320`, overwriting the complete byte rather than ORing bit 0. A separate source proof covers arbitrary atexit W0. Modeled nonzero atexit returns therefore still reach readiness publication; native exit registration success remains unknown. [NR2-NR6]

Already-ready controls execute no registration, baseline-check or atexit site and retain the original flag byte, including 3. Successful not-ready controls replace 0 or 2 with 1. Failure controls leave 0 or 2 unchanged up to their stopped common continuation; no cancel call appears before that boundary. This does not establish complete failure cleanup or the behavior of a later retry. [NR3-NR5]

All ready/success controls stop before `gettimeofday` at `0x100e203a8`, slot `0x1010b1630`, IA diversity `0x965f`, X1=NULL. Its X0 pointer is an explicit additional private fixture at F+`0x78`; its native producer, clock result and subsequent cache publication remain unknown. [NR3-NR6]

## Exit callback and cancellation boundaries

The separately entered function at `0x100df2f60` reserves 112 B and saves 96 B of registers. Its source bank rules select mutable controllers `0x1010c5498` and `0x1010c54a8`, the same dispatch base, and the three token cells. The callback reaches the following source interfaces without a native exit event. [NR2-NR5]

| Name/token class | Token load used | Cancellation site | Retained behavior |
| --- | --- | --- | --- |
| V1 | u32 at `0x1010ca2c0` | `0x100df3114` | Stop before import; explicit status premise begins next interval |
| V1.5 | u32 at `0x1010ca31c` | `0x100df318c` | Stop before import; explicit status premise begins next interval |
| V3 | u32 at `0x1010ca324` | `0x100df3228` | Source-classified tail call after an unexecuted guard |

All three target selections resolve import slot `0x1010b1628`, `libSystem/_notify_cancel`, IA diversity `0x7d61`. Two source intervals use modeled cancellation statuses 0 or `0xffffffff`. Neither status is inspected before the next token load. The third token and normalized import target are prepared before SP and X19..X30 are restored; the independent audit compares the restored values with callback entry. These are source requests for cancellation, not observed token retirement. [NR2-NR6]

The final retained boundary is `0x100df3218`, before `EOR X16,X30,X30,LSL#1`. The following TBZ checks bit 62, selecting `0x100df3224` when return-address bits 62 and 61 agree; otherwise the source reaches BRK at `0x100df3220`. A source query proves that predicate for arbitrary u64 X30. The accepted suffix sets modifier `0x7d61` and tail-branches via X1 at `0x100df3228`. The guard, BRK, tail branch, native PAC authentication and third cancellation implementation are not executed by these cases. [NR2-NR5]

The retained callback performs no store to the readiness byte or token cells. It does update the declared mutable controllers. Complete process shutdown, earlier readiness epochs, the effect of each native cancellation, and any other cleanup remain outside the established interval. [NR3-NR5]

## Historical name match, current provider mismatch and Mach scope

The daemon's three original strings exactly match the retained client/provider name bytes in the [ADID notification report](adid_notification_report.md). Its reference contract has SHA-256 `277b300a5bab70b2832dcd746be9f7c3dd32e77824930e57dc5a184a3c2114bc`; the archived provider thin image is identified by `ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf`. The historical provider post site is `0x100219198`. Its retained class proof and the previous daemon helper proof give the same three-way selection for the listed negative/general classes. This is a comparison of pinned source evidence, not current native event delivery. [NR1, NR7-NR8]

Fresh verification against the installed provider cannot use that historical image pin. The current `/System/Library/PrivateFrameworks/CoreADI.framework/adid` is 9,797,952 B with SHA-256 `9c872e64548288f7d1a9db5e2dbd97311e30b4df5745f52936ae277c80a4abe1`; the historical reader expects full-file SHA-256 `58eeb13dade3e1867641345b38961344fe53e6319928a1503bdb3315681fe929`. The publication verifier records this mismatch check. No address or class from the historical provider is assigned to the installed image. [NR7-NR8]

This increment establishes polling-token registration/check/cancellation interfaces, not new incoming/outgoing Mach port identities or message emissions. The separately versioned [libnotify transport report](notify_ipc_report.md) establishes shared-counter checks without a message and a fallback check RPC. Registration type/name and source call sites are now known for this daemon component, but native registration state, library build pairing, Mach right identity and actual transport selection remain unknown. Therefore its reference library emission PCs are not assigned to these daemon calls. [NR6-NR8]

The recovered ADID notification namespace provides an architectural touch point between this daemon component and the historical CoreADI invalidation mechanism. It does not by itself connect the original clock-success entry, provider request, IOKit caller, kext method, or native external response into one transaction. [NR1-NR8]

## Provenance and validation

| ID | Primary evidence / receipt | Scope |
| --- | --- | --- |
| NR1 | [Four-output helper](daemon_environment_outputs_report.md), its checks/audit and source extractor | Parent token consumers and complete negative/general argument predicates |
| NR2 | [Registration extractor](triage_evidence/recover_daemon_notification_registration.py), `source_regions`, `source_pool`, `source_fixups`, `bank_rules` | Original daemon opcodes, name bytes, original fixup words and source-derived interfaces |
| NR3 | [Checks archive](triage_evidence/daemon_notification_registration_checks.json.zst) | 80 cases, source interval journals, separate entry/return premises and nine source queries |
| NR4 | [Independent auditor](triage_evidence/audit_daemon_notification_registration.py) | Independent byte-addressed instruction lift and exact interface/effect comparison |
| NR5 | [Audit archive](triage_evidence/daemon_notification_registration_audit.json.zst) | 896 independent interval lifts, alternate fixture controls and compiled SDK assertions |
| NR6 | NR5 `SDK_checks` | Current arm64e prototypes, widths and relative header hashes |
| NR7 | [Historical ADID contract](triage_evidence/adid_notification_contracts.json.zst), [class query](triage_evidence/adid_notification_name_class64.smt2), [transport report](notify_ipc_report.md) | Exact retained name match and historical class proof; current provider identity differs |
| NR8 | [Publication verifier](triage_evidence/verify_daemon_notification_registration_publication.py), [manifest](triage_evidence/interface_manifest.json.zst) | Evidence/source pins, current provider mismatch, exact owned delta, original inputs and path hygiene |

Original daemon thin SHA-256: `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The checks/audit pin their implementations and parent dependencies. The current provider hash is a verification-time comparison, not a compatible source build. No analyst-machine paths are retained. [NR2-NR8]

The 72 registration cases cover 2 SP placements x 2 controller pairs. Each combination has 8 outcomes for each not-ready flag (0, 2): success, nonzero atexit, three individual registration failures and three individual baseline-check failures. Each ready flag (1, 3) has one bypass case. Eight separate callback cases cover 2 placements x 2 controller pairs x 2 cancellation-return statuses. The audit reruns all 80 cases with opposite backing/caller-saved patterns; registration alternatives also invert baseline outputs and atexit status. [NR3-NR5]

| Validation extent | Verified result |
| --- | ---: |
| Source cases / intervals | 80 / 448 |
| Original source visits | 33,648 |
| CPU read events / write events / logical edges | 9,224 / 4,016 / 408 |
| Explicit imported-return premises | 296 |
| Unique original instructions / opcode extent | 781 / 3,124 B |
| Original fixup records | 44 |
| Constant bank rules / selector inputs | 20 / 5,120 |
| New nonvacuous source queries, UNSAT | 9 |
| Historical class query rechecked, UNSAT | 1 |
| Independent interval lifts / source visits | 896 / 67,296 |
| Register values / NZCV values checked | 2,182,144 / 68,192 |
| Read bytes / write bytes checked | 106,368 B / 60,000 B |
| Original authenticated edges checked | 816 |
| Current SDK ABI compilation | exit 0 |
| Final common-failure / clock / exit-guard boundaries | 48 / 24 / 8 |

The nine new queries cover the complete u8 ready predicate, six u32 zero-only status gates, atexit-independent byte publication and the arbitrary-u64 exit guard equation. The 781-instruction count covers executed source intervals; the final tail/guard source is additionally retained and classified without execution. Counts do not include native import instructions or implementation execution. [NR2-NR5]

For C cases, V source visits, E byte effects, S retained source/bank bytes and Q source queries, extraction uses O(C(V+E)+S+Q) time and space excluding solver-internal cost. Independent lifting uses O(CV(R+B)+S+Q) work and journal storage for R register/flag checks and B byte effects per visit. Each SMT query has a 30 s limit. Logical archive bytes are round-trip checked after `zstd --ultra -22 -q -T1`. No native API, IPC, allocation/free, hardware PAC or IDA mutation executes. [NR2-NR6, NR8]

## Bounded continuation

| Impact | Remaining question | Falsification / next evidence |
| --- | --- | --- |
| High | How does the provider-success path reach registration with valid outputs? | Retain an uninterrupted source path across the missing provider call and output producers; verify all four output extents and ownership before joining the cuts. |
| High | What follows a failed registration/baseline check? | Continue `0x100e24d08` with its actual live frame and status; establish complete cleanup, return and later re-entry before claiming retries or leaked native registrations. |
| High | Which installed provider and libnotify paths match this daemon? | Identify current compatible builds and registration state. The historical provider fingerprint fails on the installed image, so archived address/name evidence cannot supply native pairing. |
| Medium | How are the 40 B cache records populated and retired? | Follow the pending clock/API consumers with separate, documented return premises, then establish earlier provider/lifetime joins. |
| Medium | What does a failed atexit registration imply for teardown? | Recover other original callers/cleanup sites and the actual matching runtime contract; the local byte store alone does not prove a callback is registered. |
| Low | Does any cancellation path reset readiness or token storage elsewhere? | Enumerate other writers and lifecycle epochs before generalizing the retained callback's absence of such stores. |

## Quality gates

- **QG1**: Source, ABI and evidence-boundary claims require no normative premise.
- **QG2**: NR-A1..NR-A8 list assumptions, dependent conclusions and falsification probes.
- **QG3**: Routine roles, registration/readiness/cancellation interfaces, environmental control, historical name correspondence and port/emission limits are covered.
- **QG4**: Integer widths, byte extents, frame arithmetic, case products, status predicates and validation counts are explicit and reproducible.
- **QG5**: Unjoined source entries, declared API outputs, pending failure cleanup, ignored atexit result, stopped guard and mismatched provider versions remain distinct.
- **QG6**: Original bytes/fixups, pinned receipts, independent source lifts, SDK header hashes, reference-name bytes and publication delta are verified.
- **QG7**: Continuations are bounded and impact-ranked; the broader interface investigation remains active.
