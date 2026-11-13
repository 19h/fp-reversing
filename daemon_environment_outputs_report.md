# Clock-success helper: output validation, cache and libnotify interfaces

Failure continuation: The [notification-failure report](daemon_notification_failure_report.md) follows all six nonzero registration/baseline routes through the actual epilogue and original caller consumer under declared cuts. It adds encoded null/record cleanup, four pending free sites and exact header stores. Retained helper return zero selects caller target 0x1006cdaf8; native provider outputs and ownership remain unknown.

Continuation: The [notification-registration report](daemon_notification_registration_report.md) identifies the three cached tokens as V1, V1.5 and V3 invalidation handles, recovers registration/baseline gates and readiness publication, and classifies the separate exit callback. Native token values, message emission and provider-to-helper lifetime continuity remain unknown; the installed provider differs from the historical reference.

The source-selected clock-success branch now connects continuously through a constant-return leaf to internal helper `0x100e1e5ec`. That helper validates four output pointers, clears two u64 and two u32 destinations, and selects cache, clock, notification-check or allocation paths. Three original calls resolve to `notify_check`, using distinct cached token cells. The retained paths stop before every external call. No native clock/notification result, port identity, message emission or daemon-kext pairing is established. [EO1-EO8]

```text
separate clock-success cut: 0x1007019b0
  -> source bank -> leaf 0x100001e0c -> X0 = -2
  -> source bank -> helper 0x100e1e5ec
     frame F = caller SP - 0x4a0
     any output pointer NULL -> return u32 0xffff5037
     all pointers non-NULL -> clear four destinations
       argument zero -> STOP before malloc(24)
       argument nonzero:
         flag bit 0 = 1 -> argument class -> STOP before notify_check
         flag bit 0 = 0 -> compare up to two cache keys
            hit  -> STOP before gettimeofday(F+0x390,NULL)
            miss -> preserve three undefined local copies
                    -> STOP before malloc(24)

No uninterrupted reservation-to-clock-success epoch join is asserted.
No external call executes in these paths.
```

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| EO-A1 | The pinned original daemon and parent receipts identify the source build. All address/source claims depend on them. | Rehash source/dependencies and compare original opcodes/fixup words. Native build, task and provider pairing remain unknown. |
| EO-A2 | The clock-success entry is a separate cut with explicit live premises W19=`0x79ea`, W22=`0xa6`, W23=`0x0a5cd4cf`, five source-compatible frame roots and ABI-compatible X0=0. Other entry scalars are fixtures. Caller/helper continuity depends on this cut. | Execute both internal calls and the constant leaf without register/PC replacement. Check exact callee-entry arguments and SP. Require an uninterrupted earlier epoch before joining this cut to the reservation or retained IOKit caller. |
| EO-A3 | Mutable controller, cache, flag and token values are declared private image fixtures. File-unbacked image spans begin with declared zero-fill. Environment branches depend on those states. | Vary two controller pairs, two SP placements, flags 0..3, both cache-hit positions and miss; independently lift opposite physical backing patterns. These fixtures are not observations of native initialization. |
| EO-A4 | Direct null-pointer and argument-class controls describe additional helper contexts, separate from the original caller, which supplies four non-null frame pointers. | Exercise all fifteen nonzero null masks and nine argument controls; do not infer that the original caller can produce those direct contexts. |
| EO-A5 | Three pure load/store pairs may carry undefined bytes without defining them. Miss-path continuation depends on preserving this distinction. | Prove each complete copy for arbitrary u64 input, propagate all 24 origins and zero definedness masks, then reject any undefined read outside those pairs or unknown-dependent address/branch. Compare opposite backing patterns. No native uninitialized-data defect is inferred. |
| EO-A6 | Normalized targets and original diversities describe logical source edges; the stack-canary storage is an explicit private fixture. | Independently decode 38 original fixup words, validate authenticated edges, separately decode the unauthenticated canary bind, and check source canary/epilogue behavior on direct rejection paths. Hardware PAC is not executed. |
| EO-A7 | Current arm64e SDK declarations provide an ABI comparison for imported functions. Native libnotify implementation/version pairing is unknown. | Compile prototype/width/layout assertions against hashed relative SDK headers; keep the separately versioned libnotify transport report distinct from this daemon source call. A notify token is not a Mach port name. |
| EO-A8 | Publication covers only the owned increment. Preservation claims depend on its exact delta. | Verify source/audit pins, manifest/input preservation, compressed round trips and raw/typed/decoded-payload path hygiene. The full goal remains active. |

## Continuous local caller and output ABI

The original two-bank decoder at `0x1007019b0` uses key `0xe4`; all 256 inputs reduce to constant `0x5d`. The first selection is index `0xcc6c`, slot `0x1010a0250`, target `0x100001e0c`, IA diversity `0x2a84`. The complete leaf is `MOV X0,#-2; RET`. It returns u64 `0xfffffffffffffffe`; no descriptor or selector meaning is assigned from that value alone. [EO2-EO5]

The second selection uses index `0xcc1d`, slot `0x10109ffd8`, target `0x100e1e5ec`, IA diversity `0xde8e`. Its actual source call is at `0x100701a78`. Forty-eight caller profiles execute the caller, constant leaf and helper as one path, stopping at the first import. The five frame-root values are explicit source-compatible premises, not a new initializer-to-caller lifetime proof. [EO2-EO5]

| Helper argument | Source value | Access contract established here |
| --- | --- | --- |
| X0 | Full u64 `-2` from the original leaf | Nonzero argument; belongs to the common negative notification class |
| X1 | S+`0x8950` | Pointer to one u64 output cell |
| X2 | S+`0x78b8` | Pointer to one u32 output cell |
| X3 | S+`0x73c0` | Pointer to a second u64 output cell |
| X4 | S+`0x630c` | Pointer to a second u32 output cell |

Here S is caller SP. The helper saves 96 B, establishes FP=S-`0x10`, then reserves 1088 B, giving F=S-`0x4a0` and a total 1184 B frame. These byte counts describe the observed save/local reservation. They do not establish a recovered C structure or native object owner. [EO2-EO5]

`0x100e1e738..0x100e1e764` establishes the complete predicate that all four pointers are nonzero. If any is zero, the helper selects index `0x1b2` in its separate dispatch table, checks the canary and restores SP and X19..X29, returning u32 `0xffff5037`. All fifteen direct null-mask controls take this route without any output store or import. [EO2-EO5]

When all four pointers are nonzero, `0x100e1e7e0`, `...7e8`, `...7f0`, `...7f8` clear the destinations in argument order with widths 8, 4, 8, 4 B. The source also clears three local changed-result cells used by the notification routes. Destination validity beyond the declared environments remains unknown. [EO2-EO5]

## Flag, cache and token selection

The pointer-bank rules separately resolve mutable controller roots `0x1010c54d8` and `0x1010c54a8`, dispatch base `0x1010abb60`, cache base `0x1010ca2c8`, flag byte `0x1010ca320` and three notification-token cells. Fifteen bank rules retain both 256 B arrays and all 256 XOR outputs. Their exact constant identities do not require stable controller values between separate source reads; original table/bank epochs remain a premise. [EO2-EO5]

For a nonzero argument, the flag predicate uses only bit 0 of the byte at `0x1010ca320`. Flags 0/2 take lookup; flags 1/3 take direct notification classification. The universal source query covers every u8 flag, rather than only those four controls. Argument zero bypasses this selection and reaches the allocation frontier in its direct control. [EO2-EO5]

Lookup starts at signed index 0. The original key address is `cache_base + 40*s64(s32(index32))`; it compares one u64 key with the full incoming argument. The miss increment uses signed comparison against 2. Starting from 0 therefore examines records 0 and 1 before the miss continuation. This establishes key stride40 B and the selected two-record search; the other bytes in the declared 80 B cache fixture are not recovered as a complete payload ABI here. A hit at either position selects a second clock call at `0x100e1ee5c`, with X0=F+`0x390`, X1=NULL. [EO2-EO5]

The notification route implements these exact classes. Addition and range comparison are modulo 2^64 and unsigned; the negative notation in the table denotes the corresponding two's-complement u64 value. `ULT(argument+6,5)` selects -6 through -2. Separate equality tests select -1 and -8; -7 belongs to the general class. [EO2-EO5]

| Argument class | Token source, u32 | Original call site | Changed-result pointer |
| --- | --- | --- | --- |
| -8, -6, -5, -4, -3, -2 | `0x1010ca324` | `0x100e1f2d8` | F+`0x194` |
| -1 | `0x1010ca31c` | `0x100e1f498` | F+`0x158` |
| Other nonzero values | `0x1010ca2c0` | `0x100e1f3e4` | F+`0x17c` |

All three calls resolve import slot `0x1010b16a8`, symbol `libSystem/_notify_check`, IA diversity `0x89e0`. The current SDK declares `uint32_t notify_check(int token, int *check)` with 4 B int/u32 and 8 B pointers. The source clears each corresponding local before the call. Token fixtures `0x5034`, `0x5036`, `0x5035` distinguish the three source roots; their native values, registered names, registration types and service associations are unknown. No imported call or changed-result write by libnotify executes here. The original caller's constant -2 belongs to the common class. [EO2-EO6]

Argument zero is a separate direct-helper control. It reaches the allocation frontier despite the declared flag being 1. This does not imply that the clock-success caller supplies zero; its original leaf supplies -2. [EO2-EO5]

## Undefined copies and allocation frontier

On the retained cache miss, three original u64 load/store pairs copy frame bytes whose producers are outside this cut. The evidence keeps these bytes undefined at both ends. [EO2-EO5]

| Load / store PC | Source | Destination | Width |
| --- | --- | --- | --- |
| `0x100e1f1e8` / `0x100e1f1ec` | F+`0xe8` | F+`0x240` | 8 B |
| `0x100e1f1f0` / `0x100e1f1f4` | F+`0xd0` | F+`0x248` | 8 B |
| `0x100e1f1f8` / `0x100e1f1fc` | F+`0xa0` | F+`0x250` | 8 B |

Each pair is proved to preserve an arbitrary u64 value. CPU journals retain byte origins and zero definedness masks; the independent lift uses fresh symbolic byte origins. Changing every otherwise undefined physical byte between patterns `0x35` and `0xca` preserves control, boundaries and all known write effects. Undefined-byte address/branch dependencies and reads outside these three copy pairs are rejected. The cut does not establish a native uninitialized-data defect, an external disclosure or a later consumer of these copies. [EO2-EO5]

The miss and direct zero-argument routes stop at `0x100e1ea4c`, before `malloc(24)`, import slot `0x1010b1358`, IA diversity `0x57e4`. Thus 24 B is the requested allocation extent; allocation success, returned address, initialization, object format, ownership and later four-output publication are unknown. The two cache-hit routes instead stop before `gettimeofday` at `0x100e1ee5c`, slot `0x1010b1630`, IA diversity `0x965f`. No allocation or clock return premise is inserted. [EO2-EO6]

## Separate caller return consumer

The caller's original suffix at `0x100701a7c` remains unexecuted on the non-null helper paths. A separate source equation proves its complete status split for every u32 return, with W21=`0x1cb7` derived from the caller. Define all operations below modulo 2^32:

```text
d     = result32 - ((result32 << 1) & 0x167b8ca2)
W28   = d + 0x8b3dc651
d == 0  <=>  result32 == 0
```

| Predicate | Table index | Original slot | Target | IA diversity |
| --- | --- | --- | --- | --- |
| result32 = 0 | `0x79ea` | `0x101076e40` | `0x1006cdaf8` | `0x4113` |
| result32 != 0 | `0x7a10` | `0x101076f70` | `0x100709868` | `0x4113` |

This is a zero-only caller status gate. It does not give a business meaning to either target or establish a helper return after any pending import. Direct null-output controls return u32 `0xffff5037` before this consumer; they do not supply an execution join from the original caller. [EO2-EO5]

## Mach accounting and external control

No incoming/outgoing Mach port, right operation or message-emission site is established by this increment. It establishes three daemon call sites that may enter libnotify, with cached integer tokens and local changed-result cells. Whether any call emits a message depends on the native registration and libnotify path, neither of which is identified here. [EO2-EO7]

The separately versioned [libnotify transport report](notify_ipc_report.md) establishes a shared-counter path with no Mach emission and a fallback check RPC, message 1002, at reference-image PC `0x1805947a0`. Those library facts are not automatically a daemon call-to-message mapping. A native token-to-registration join and matching library identity are required before assigning that emission to any of the three daemon sites. Likewise the token integers are not port names, and the cache does not establish a FairPlayIOKit connection or provider. [EO7]

The helper's observed external inputs are the incoming argument and four output addresses, mutable controllers, flag, cache keys and token cells. Original source writes update controllers. The cache lookup, direct-notify selection and pending imports make this an environmental cache/check component under the stated premises; complete output semantics and the larger operation remain unknown. The retained IOKit caller still lacks an uninterrupted producer/lifetime join. [EO1-EO5]

The current MCP connection exposes a different image and no matching daemon database. No unrelated IDB bytes or memories enter these claims, and no current daemon-IDB verification is asserted. The pinned original file and prior receipts suffice for the source claims above.

## Provenance and reproducibility

Addresses are unslid addresses in the pinned original thin daemon; private S/F addresses are fixture-relative. Primary evidence is executable source bytes, original fixup words and the SDK headers compared by the audit. [EO2-EO6]

| ID | Evidence | Scope |
| --- | --- | --- |
| EO1 | [Scratch-pointer origin](daemon_scratch_pointer_origin_report.md) and its pinned checks/audit | Parent selection of the separate clock-success cut; no continuous earlier join |
| EO2 | [Source extractor](triage_evidence/recover_daemon_environment_outputs.py), `source_regions`, `source_pool`, `source_fixups` | Original opcodes, complete leaf, local branches/calls, caller suffix and 38 original fixup records |
| EO3 | [Checks archive](triage_evidence/daemon_environment_outputs_checks.json.zst) | 72 CPU cases, complete source journals, fixtures, 15 bank identities and 12 source queries |
| EO4 | [Independent auditor](triage_evidence/audit_daemon_environment_outputs.py) | Independent byte-addressed source lift, unknown origins, register/NZCV/effect/edge comparison and ABI compile assertions |
| EO5 | [Audit archive](triage_evidence/daemon_environment_outputs_audit.json.zst) | 144 independent lifts, opposite backing controls, interface checks and header hashes |
| EO6 | EO5 `SDK_checks` | Current arm64e C prototype/width/layout comparison; no original SDK or native implementation match |
| EO7 | [libnotify transport report](notify_ipc_report.md) | Separately versioned library/notifyd transport evidence; no daemon token/port join |
| EO8 | [Publication verifier](triage_evidence/verify_daemon_environment_outputs_publication.py) and [manifest](triage_evidence/interface_manifest.json.zst) | Exact owned delta, evidence pins, original-input preservation and path hygiene |

Original thin SHA-256: `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Parent checks/audit and implementation dependency hashes are embedded in EO3/EO5. Header hashes are relative to the SDK; no analyst-machine paths are retained.

The 48 continuous caller profiles cover 2 SP placements x 3 cache modes x 4 flag values x 2 controller pairs. Fifteen direct controls cover every nonzero four-pointer null mask. Nine additional direct controls distinguish argument classes and the zero bypass. The resulting frontiers are 32 notification checks, 16 cache-hit clock calls, 9 allocations of 24 B and 15 null-output returns. [EO3-EO5]

| Validation extent | Verified count |
| --- | ---: |
| CPU cases / original source visits | 72 / 22,730 |
| CPU reads / writes / logical edges | 5,364 / 3,639 / 417 |
| Unique source instructions / opcode extent | 579 / 2,316 B |
| Retained original fixup records / separate return-selector slots | 38 / 2 |
| Source bank rules / selector inputs checked | 15 / 3,840 |
| Nonvacuous source queries, UNSAT | 12 |
| Independent lifts / source visits | 144 / 45,460 |
| Register values / NZCV values compared | 1,459,328 / 45,604 |
| Read bytes / write bytes compared | 61,606 B / 54,664 B |
| Original authenticated edges checked | 708 |
| Undefined copy bytes checked, reads plus writes | 768 B |
| Current SDK prototype/layout compilation | exit 0 |

The extractor uses O(C(V+E)+S+Q) time and space for C cases, V visits and E effects per case, S retained source/bank bytes and Q proof queries, excluding solver-internal cost. The auditor uses O(C(V(R+B))+Q) work and journal storage for R register/flag comparisons and B byte effects per visit. Each SMT query has a 30 s limit; stored results are checked again by the publication verifier. Archive round trips preserve logical bytes. No native API/IPC, allocation/free, hardware PAC or IDA mutation executes. [EO2-EO6, EO8]

## Bounded continuation

| Impact | Remaining question | Falsification / continuation |
| --- | --- | --- |
| High | What registers the three cached tokens and defines the flag? | Trace original writers and initialization epochs for `0x1010ca324`, `0x1010ca31c`, `0x1010ca2c0`, `0x1010ca320`; require actual names, registration kinds and matching image before a Mach mapping. |
| High | How do cache hit/miss paths populate the four outputs? | Recover each pending import's source return consumers under explicitly separate ABI premises, then establish complete cache payload widths, initialization and ownership. |
| High | Does this helper feed the retained FairPlayIOKit transaction? | Establish an uninterrupted source path and frame/cursor lifetime from reservation through the clock-success cut to the retained caller. Matching offsets or status encodings alone cannot establish the join. |
| Medium | Where do the three copied local values originate? | Trace F+`0xe8`, F+`0xd0`, F+`0xa0` writers in an earlier context; require retained definedness before attributing values or defects. |
| Medium | Which native notification path is selected? | Match daemon/library builds and token registration state to the independently recovered shared-counter or RPC implementation. |
| Low | Can the four-output helper receive aliased or invalid pointers outside this caller? | Enumerate additional original callers before extending the non-null source contract to native pointer validity or a public ABI. |

## Quality gates

- **QG1**: Technical source/ABI claims only; no normative premise is required.
- **QG2**: EO-A1..EO-A8 enumerate assumptions, dependent results and falsification probes.
- **QG3**: Routine roles, local control/data flow, environmental interfaces, port/emission limits and continuation are reported separately.
- **QG4**: u8/u32/u64 widths, modular equations, signed cache indexing, byte extents, frame arithmetic and validation counts are explicit and reproducible.
- **QG5**: Separate entry cuts, direct controls, undefined copies, pending imports, current SDK comparison and native unknowns remain distinct; no unresolved contradictory result is promoted to a claim.
- **QG6**: Original opcodes/fixups, dependency hashes, independent journals, header hashes and the exact publication delta are verified.
- **QG7**: Continuations are bounded and impact-ranked. The full interface investigation remains active.
