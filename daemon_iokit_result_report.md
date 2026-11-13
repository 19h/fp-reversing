# Daemon selector-21 result gates, copyback and error cleanup

Subsequent return evidence: The [error-return continuation](daemon_iokit_error_return_report.md) resumes the eight selected error boundaries through actual root/adapter returns, zero delta and caller recognition. It adds eleven source equations and 16 independent replays / 8,400 new A64 visits. After a private marker and common preparation, it stops before using an unspecified u64 bank root at caller SP+0x600. The boundaries and zero/zero helper stops recorded below are preserved as this parent increment's scope; complete external response and native delivery remain unknown.

The daemon has two separate zero gates after its pending selector-21 IOKit call. The first tests the API return; only the zero branch reads the embedded u32 status at API-buffer+`0x224`. A nonzero embedded status then joins the API-error cleanup path. Under independently declared API-return/output premises, both selected error paths request free of the same preceding 32 B allocation and publish their distinct encoded statuses in the original root record. With both statuses zero, source instead consumes the output count and reaches a different pending helper. Extended mode also copies 16 returned bytes through XOR `0x98` into a construction-derived span. These are source contracts and private A64 replays; native API success, copyout and daemon-kext transaction pairing remain unknown. [IR1-IR8]

```text
pending selector 21 at 0x100478a04
  separate API-return/output premise; import is not executed
  |
  +-- API status != 0 ------------------------------+
  |                                                |
  +-- API status == 0 -> read buffer+0x224           |
        |                                          |
        +-- unspecified -> STOP before arithmetic  |
        |                                          |
        +-- status != 0 ---------------------------+
        |                                          |
        +-- status == 0                             v
              |                          original pair-retirement helper
              |                          overwrite 32 B -> pending free(A)
              |                            separate ordinary void return
              |                          -> root R+8 = encoded error
              |                          -> STOP before root canary/epilogue
              |
              +-- extended mode: 16 B XOR98 copyback
              +-- read buffer+0x220 count
              +-- prepare raw/encoded count + spans
              +-- STOP before helper 0x100436388
```

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| IR-A1 | The pinned daemon image and exact pending-call parent receipts identify the analyzed build and source epochs. All joins depend on them. | Rehash dependencies and parent receipts; check every retained instruction and original fixup. Native daemon/kext build, task, connection and provider pairing remain unknown. |
| IR-A2 | The preceding declared private interior objects, caller records, stable controller/bank fixtures and valid frame/extent premises remain in force. Reaching paths depend on them. | Restore the preceding source journals and independently re-execute the post-block parent path. Original unresolved ingress fixtures are preserved; native caller admission is not inferred. |
| IR-A3 | A normally returning IOKit API supplies a selected u32 status and exactly the listed output effects; other modeled memory is preserved. Post-call continuations depend on these separate hypotheses. | Retain API=5, API=0 with unspecified output status, API=0 with embedded `0xffff5a5e`, and independent zero/zero count controls. No API import or transport executes; unlisted native memory effects remain unknown. |
| IR-A4 | Ordinary API/free returns preserve SP, X18-X29 and low 64 bits of Q8-Q15, while other caller registers/flags are arbitrary. Later source uses depend on that ABI premise. | Keep opaque model-byte origins distinct from source bytes; replay two concrete backing/clobber patterns and verify preserved registers and D8-D15. The source equations omit incidental volatile-register values. Native PAC/signing, faults and scheduling remain unknown. |
| IR-A5 | The separate ordinary free return makes no model memory writes; retiring A is analysis bookkeeping. Result-publication and access claims depend on it. | Retain the exact pending free and argument first; independently reject later source reads/writes intersecting A's 32 B span. No native ownership or actual destruction is inferred. |
| IR-A6 | Algebraic slices use valid distinct source-cell contracts and the reaching phase literals. Universal scalar/byte equations depend on that scope. | Re-run all eight nonvacuous UNSAT queries; verify the actual phase values and byte addresses in finite cases. These equations do not prove arbitrary aliasing, native pointers or all possible controller epochs. |
| IR-A7 | The prior kernel-produced `0xffff5a5e` is supplied only as a separate API-output compatibility control. Cross-layer interpretation depends on this boundary. | Pin the wrapper receipt and verify the exact scalar and field offset. No native copyout, same transaction, receiver identity, complete buffer equality or successful mode-5 provider execution is inferred. |

## API result and embedded status are separate gates

The [post-block dispatch report](daemon_postblock_dispatch_report.md) stops before `_IOConnectCallStructMethod` at `0x100478a04`, with selector 21, input size 552 B and equal user input/output addresses. This increment starts at `0x100478a08` under a separate return premise. Let F be the retained root SP and B=`F+0x6a8` the API buffer. The u64 API capacity cell is `F+0x3f0`; it is separate from the u32 protocol count B+`0x220`. [IR1-IR4]

Original instructions `0x100478a0c..0x100478a24` compute `W28 = API_status32 XOR 0x8b3dc651`. The next comparison uses W21=`0x2699`, making its target encoded zero. For every u32 API status under the retained phase contract, the first table index is `0xb464` iff API status is zero; otherwise it is `0x92b2`. The pointer roots and phase values come from the actual preceding source boundary, rather than arbitrary table fixtures. [IR3-IR6]

| Gate / condition | Original table index | Original authenticated target |
| --- | --- | --- |
| API != 0 | `0x92b2` | `0x10062c4bc`, IA diversity `0x404c` |
| API == 0 | `0xb464` | `0x10061ada0`, IA diversity `0x404c` |
| Embedded status != 0, after API == 0 | `0x2699` | Same `0x10062c4bc`, distinct IA diversity `0x1a02` |
| Embedded status == 0, after API == 0 | `0x31c6` | `0x1003ec8e8`, IA diversity `0x1a02` |

The same error target has two original slots/discriminators. A same-address match alone does not identify the incoming edge. Original format-12 fixups and each actual target/modifier pair are retained. [IR3-IR6,IR8]

Only the API-zero path reads B+`0x224`, at `0x10061adc4`. Subsequent instructions compute `W28 = embedded_status32 XOR 0x8b3dc651` and test the raw embedded word for zero. With no declared status output, all four bytes retain unspecified origins; execution stops before transforming them at `0x10061adc8`, after 30 retained instructions. Physical backing values in independent replays do not convert those bytes into logical definitions. [IR3-IR6,IR8]

The [wrapper-return report](versioned_wrapper_error_return_report.md) supplies a kernel source return `0xffff5a5e` and a separate UserClient output+`0x224` store. This increment consumes that scalar as an independently declared output effect. It establishes source compatibility between the two field contracts; native delivery remains unknown. [IR2-IR4,IR7]

## Selected errors preserve their cause through cleanup

| Declared API/output control | Output status read? | Retained daemon root R+8 result |
| --- | --- | --- |
| API status 5; no output writes | No | `5 XOR 0x8b3dc651 = 0x8b3dc654` |
| API status 0; embedded status `0xffff5a5e` | Yes | `0xffff5a5e XOR 0x8b3dc651 = 0x74c29c0f` |

These two concrete controls exercise the universal first-gate equations and complete finite error continuations. They are not observations of native API error 5 or a native protected-operation result, and no business status names are assigned. [IR3-IR6,IR8]

Both routes join `0x10062c4bc`, traverse `0x10048d88c`, and reach original call `0x1004bfb58 -> 0x100439874`, IA diversity `0x905f`. The actual reused inner record selects the same pointer-pair retirement helper previously established in the [root lifecycle report](daemon_versioned_root_report.md). Its retained pair is `(A,0)`, with A the exact preceding 32 B allocation. The helper skips the null member, overwrites A's bytes in descending order 31..0, then stops before `_free` at `0x1002dc500`. Original slot `0x10109ff30` binds `libSystem/_free`, IA diversity `0x46a2`; X0 is A. [IR3-IR5,IR8]

After a separate ordinary void-free return, 30 further source instructions return from that helper and publish W28 at root R+8 using `0x100309cd8`. R is the actual preceding caller-produced record, at caller SP+`0x10cb8`. No later source access intersects logically retired A. The final boundary is `0x100309cdc`, before the root canary load/check and frame epilogue. Complete root return, adapter continuation and external response remain outside these intervals. Native lifetime and destruction remain unknown. [IR3-IR5,IR8]

There are eight error controls across four parent contexts. They check `8*32=256 B` of descending allocation overwrites and eight distinct root-result publications. No API-buffer byte is written by the retained post-call source. The only changes to that buffer are the separately listed API-output hypotheses. [IR4,IR8]

## Zero/zero count and extended-span consumers

Two independent zero/zero controls retain count 16 or supply count 512 at B+`0x220`. These are successful-status controls, separate from the provider-absent error path. The original source reads the u32 count at `0x10061bed8` and prepares a record: [IR3-IR6,IR8]

| Original source PC | Record / span effect |
| --- | --- |
| `0x10061becc` | F+`0x580` receives the saved construction pointer from F+`0x3f8`. |
| `0x10061bedc` | F+`0x588` receives raw u32 COUNT. |
| `0x10061bf04` | F+`0x58c` receives COUNT XOR `0x8b3dc651`. |
| `0x10061bf10`, `0x10061bf14` | F+`0x590` and F+`0x598` receive `F+0x6c8 = B+0x20`. |
| `0x1004d6d94` | Pending call to `0x100436388`, IA diversity `0xde8e`, with the next source-built record in X0. Its body remains unexecuted. |

No new retained path reads the u64 capacity cell F+`0x3f0`. The source count-forwarding equation quantifies over all u32 counts for this phase/cell contract. The finite 16/512 controls establish their reaching record values; they do not establish provider capacity compliance, successful processing, complete output bounds or the semantics of the pending helper. [IR3-IR6,IR8]

Before consuming count, the extended-mode zero/zero route executes `0x10047455c..0x1004746ec`. It reads B+`0x0c..0x1b` in descending order and writes 16 bytes to the source pointer saved at F+`0x488`, equal to F+`0x620` in these contexts. The prefix route skips this copy. Its universal byte equation is: [IR3-IR6,IR8]

```text
destination[j] = API_buffer[0x0c+j] XOR 0x98
j = 15,14,...,0
destination = saved source pointer; retained destination = F+0x620
```

The earlier mode-5 request stage serialized the corresponding construction bytes through the same XOR. Under this turn's declared preservation of those API-buffer bytes, the two transforms cancel. This does not establish that a native provider leaves them unchanged or that the destination owns a key or plaintext. Four finite controls check 64 copied bytes; independent replay checks both physical backing patterns. The field's application meaning remains unknown. [IR2-IR6,IR8]

## Provenance and verification

| ID | Primary evidence |
| --- | --- |
| IR1 | Original daemon SHA256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; retained source words are checked against original image bytes. |
| IR2 | Pending-call parent receipt SHA256 `3cd216630458c65aa34c0f2b1f6155c35a7cfc8206eb97b0fdcc6788e0b401b0`; wrapper receipt `745b927fe59d20ae447a18c49d99656dc0096a7ab37a7220dbe6126e772d0ae4`. Four parent contexts cover two epochs and prefix/extended modes. |
| IR3 | [Extractor](triage_evidence/recover_daemon_iokit_result.py): exact parent restoration, separately declared API/output effects, opaque caller clobbers, original cleanup, guarded logical retirement and count/span consumers. |
| IR4 | [Compressed source receipt](triage_evidence/daemon_iokit_result_checks.json.zst): 20 controls / 28 intervals, 15,612 new source visits, 1,448 read events and 968 write events. Earlier restored journals are excluded from those totals. |
| IR5 | Eight nonvacuous UNSAT source equations: API encoding/gate, protocol encoding/gate, count/span setup, count encoding, root result publication and the complete 16-byte XOR copyback. |
| IR6 | Fresh original code captures for both gates, error merge, count consumer, root result and extended copyback; original authenticated branch slots and exact free binding. |
| IR7 | [Independent A64 auditor](triage_evidence/audit_daemon_iokit_result.py) and [compressed audit](triage_evidence/daemon_iokit_result_audit.json.zst): two backing/clobber patterns per control, separate parent-prefix accounting, every source register/memory/control effect, strict unresolved frontier, exact field roles, descending cleanup and retirement guards. |
| IR8 | [Publication verifier](triage_evidence/verify_daemon_iokit_result_publication.py): pinned source/audit producers, original fixups, source equations and interface joins, replay coverage, exact manifest delta, preserved originals, lossless archives and decoded-path hygiene. Associated files suffice; no new IDA access, native API or Mach transaction occurs. |

Per parent, API-error intervals contain 1,603+30 visits; unspecified protocol status contains 30; the supplied provider-error word contains 1,626+30. Prefix zero/zero controls contain 259 visits each; extended controls contain 325 each. Thus `4*(1633+30+1656)+4*259+4*325=15,612`. Forty independent case/pattern replays cover 56 intervals / 31,224 new source visits. Earlier independently replayed post-block prefixes are separately counted. Extraction and audit use O(restored receipt bytes+C*V+I+Q) time/space plus solver cost capped at 30 s/query, with at most 20,000 visits per new interval. Large JSON and the manifest are losslessly roundtripped zstd level-22 archives.

The independent new-source replays check 18,912 read bytes, 9,536 write bytes, 27,896 register effects, 720 NZCV effects and 1,936 write events. They separately execute 13,300 original parent-prefix instructions; those visits are excluded from the 31,224 new-source total. Unknown copied-byte writes total zero; arbitrary register/backing origins remain model inputs. [IR7-IR8]

No new Mach port, right operation or message emission is established. The IOKit and free imports remain unexecuted; their return effects are explicit premises. Native build/task/connection/provider pairing, authorization, memory ownership and external response remain unknown. [IR3-IR4,IR7-IR8]

| Impact | Further bounded work | Required evidence |
| --- | --- | --- |
| High | Complete the selected daemon error response. | Reaching root canary/epilogue, adapter delta/result forwarding and actual caller recognition, without substituting an unrelated saved frame. |
| High | Recover the zero/zero processing helper's record contract. | Decode the actual source-built record, distinguish saved construction span from B+0x20, and follow count use and write bounds before assigning field semantics. |
| High | Establish native result delivery. | One matched build/task/connection/provider epoch with actual API return, copyout, embedded fields and daemon consumer. Static scalar compatibility alone is insufficient. |
| Medium | Establish the extended 16 B field's complete contract. | Source writers, API/provider modifications, copyback consumers, alias/lifetime guards and application meaning. |
| Medium | Generalize error and retirement paths. | Other u32 statuses, controller epochs, both-populated/aliased pointer pairs and real allocation/free effects. Universal local gates do not alone prove whole-path behavior. |

- **QG1**: Pass. Factual source/ABI/control/data-flow analysis requires no normative content.
- **QG2**: Pass. IR-A1..IR-A7 identify assumptions, dependent results and falsification probes.
- **QG3**: Pass for this increment. API/protocol separation, strict unknown frontier, selected error cleanup/publication, count forwarding and extended copyback are covered. The full goal remains active.
- **QG4**: Pass. u32 XOR arithmetic, u64 capacity versus u32 field, 552 B structure, 32 B allocation, 16 B copyback, offsets and source/replay/prefix accounting are explicit.
- **QG5**: Pass. API/protocol errors, distinct slots to the same target, source/API writes, core, private and native identities, declared free/logical retirement and universal-slice/finite-path results remain distinct.
- **QG6**: Pass. Original bytes/fixups, pinned parents, eight source equations, independent original-A64 effect checks and publication/preservation/path audits supply scoped provenance.
- **QG7**: Pass. Full response, zero/zero helper, native result delivery, extended-field semantics and retirement generalization are bounded and impact-ranked above.
