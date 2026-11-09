# FairPlay XPC record discriminators, value encodings, and constructor ABI

The initial fitted record has a BE32 first word H, a BE16 discriminator T, a BE32 extent P, and payload at offset 10. The selected discriminator tree recognizes exactly three T values: `0x9777` decodes a BE32 payload with P=4 B, `0x8485` decodes BE64 with P=8 B, and `0x50db` takes the variable-byte branch. That third branch tests **H==0**, not P==0, before taking its result continuation. A local 32 B argument record and two subsequent allocations establish another representation boundary; application command meanings, later iteration/dispatch, authorization, reply emission and daemon/kext linkage remain unknown [XR1-XR7].

Primary evidence: [original bytes, calls and branches](triage_evidence/daemon_xpc_records_source.json), [checks and retained queries](triage_evidence/daemon_xpc_records_checks.json), [capture script](triage_evidence/recover_daemon_xpc_records.py), [validator](triage_evidence/validate_daemon_xpc_records.py), [preservation seal](triage_evidence/daemon_xpc_records_delivery.json), and [quality gates](triage_evidence/daemon_xpc_records_quality_gates.json). The pinned daemon SHA-256 is `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The [preceding payload report](daemon_xpc_payload_report.md) supplies the full-u64 length L, low32 copy extent N, separate 16 B allocation Q and initial `10+P<=N` gate. Current local references suffice; no additional IDA query, target execution or knowledge-store recall is performed.

```text
copied input M, initial cursor 0, extent gate satisfied
  |
  +-- H=BE32(M+0), T=BE16(M+4), P=BE32(M+6)
        |
        +-- T=9777 --> P=4 --> BE32 value ----------------+
        +-- T=8485 --> P=8 --> BE64 value ----------------+
        +-- T=50db --> pointer M+10; save end 10+P        |
                           +-- H!=0 ---------------------+
                           +-- H==0 --> publish Q        |
        other T / wrong fixed extent --> failure frontier|
                                                        v
                                             local argument record:32 B
                                                        |
                                             malloc(32), malloc(P+10)
                                                        |
                                             0x100b067d8 frontier
```

## Header and discriminator mappings

| Input bytes relative to initial cursor | Decoded quantity | Selected internal form |
|---|---|---|
| 0-3 | H, BE32 | W4=`H XOR 0x8b3dc651` |
| 4-5 | T, BE16 | W10 low16=`T XOR 0x11c3`; signed decision value `s16((T XOR 0x11c3)+3)` |
| 6-9 | P, BE32 in B | W24=`P XOR 0x8b3dc651` |
| 10 onward | Payload | Representation depends on T below |

At `0x100cc0944`, the obfuscated address expressions reduce to cursor+0, +1, +2 and +3 for every 64-bit cursor bit pattern; this is an arithmetic identity, not proof of pointer validity. Dynamic W shifts reduce to 24 and 16; the remaining byte uses shift 8. The arithmetic/Boolean decode is proved over all 32-bit H values. The first word is called H throughout: identifier, lookup key, operation selector and authenticated meaning are **unknown** [XR2-XR5].

| Wire T | Stored low16 form | Selected value role | Additional condition | Value destination / continuation |
|---|---|---|---|---|
| `0x9777` | `0x86b4` | Unsigned BE32 payload | P=4 B | `0x100a8a6b4`; SP+`0x42c` receives `value32 XOR 0x8b3dc651` |
| `0x8485` | `0x9546` | Unsigned BE64 payload | P=8 B | `0x100a611b8`; SP+`0x358` receives `value64 XOR 0x2c220a381b62f9ab` |
| `0x50db` | `0x4118` | Variable byte reference | H!=0 selects construction | `0x100a85d74`; SP+`0x388` receives M+10, SP+`0x450` receives 10+P |
| `0x50db` | `0x4118` | Result frontier | H=0, independently of P | `0x100c8f210` / index `0x3b5c` |
| All other 65533 T values | Varies | Discriminator rejection frontier | Within this selected tree | `0x100bd9558` |

The tree first compares the transformed signed 16-bit value against signed `0x9549` (-27319), then against `0x411b` (16667). Equality leaves are `0x86b7`, `0x9549` and `0x411b`. The exact membership is proved symbolically and enumerated for all 65536 T patterns. This is discriminator membership, not whole-protocol acceptance: the outer extent gate, fixed-size checks and downstream processing remain separate prerequisites [XR4-XR6].

The fixed-size comparisons are at `0x100b09c30` (encoded P equals `0xabffbeeb`, hence P=4) and `0x100c2bf60` (encoded P equals `0xabffbee7`, hence P=8). Both scalar branches reach `0x100a18fcc`, which saves the previously computed end offset at SP+`0x450`, then joins argument loading at `0x100ab3e34`.

For the variable branch, `0x100a85d94` compares W14 with `0xabffbeef`. W14 at this point is **H XOR 0xabffbeef**, produced while decoding bytes 0-3. It is not the earlier encoded P: that earlier value was in W13, and P's retained form is W24. The retained proof includes equivalence of this equality to H=0, and four Boolean model cases vary H-zero and P-zero independently. A nonzero H with P=0 still selects the construction branch, assuming the inherited outer gate and frame contract. No application-level terminator, empty-value or command semantics are assigned [XR4-XR6].

## Local argument and allocation ABI

At `0x100a86128`, Q is saved at SP+`0x7e0`; the helper continuation loaded from table index `0x21f` is saved at SP+`0x538`. The following stores assemble a 32 B local record at SP+`0xa40`:

| Offset in local record | Width | Selected stored value |
|---|---|---|
| +0 | 4 B | Encoded H |
| +4 | 2 B | Unwritten in this selected record setup; unknown |
| +6 | 2 B | `T XOR 0x11c3` |
| +8 | 4 B | Encoded P |
| +12 | 4 B | Encoded BE32 value, or inherited encoded zero for the first non-BE32 record |
| +16 | 8 B | Encoded BE64 value, or inherited encoded zero for the first non-BE64 record |
| +24 | 8 B | M+10 for the variable branch; inherited NULL for the first scalar record |

The inherited setup writes `0x8b3dc651` to SP+`0x42c`, `0x2c220a381b62f9ab` to SP+`0x358`, and zero to SP+`0x388`. These establish the first-record defaults. Reset behavior across later iterations is unknown; the defaults are not generalized to every record [XR3-XR4]. Reconstructed C++ layouts match offsets and widths; they are analytical representations, not recovered canonical Apple type declarations.

| Site / original binding | Interface | Established local arguments / writes |
|---|---|---|
| `0x1009ba548` / slot `0x10109ff58`, IA modifier `0x6aa4` | `_malloc` | W0=32 B; result saved at SP+`0x410` |
| `0x100a41df8` | Heap initialization | First 16 B of that allocation zeroed on success |
| `0x100a41efc` | Heap field store | Unsigned 32-bit `P+10` at heap object+16 |
| `0x100a41f48` / same original binding | `_malloc` | W0=`P+10` in B, zero-extended to X0 |
| `0x100a41f4c` | Heap field store | Second allocation pointer at heap object+24 |
| `0x100bd66d4` | Selected next branch | Original table index `0x3b96` -> `0x100b067d8` |

The helper's pre-allocation arithmetic recovers P exactly and checks unsigned `P < 0xfffffff6`, equivalent to P<=4294967285 B. This ensures P+10 does not wrap 32 bits. The preceding initial-fit condition `uint64(P)+10 <= uint64(N)` implies this bound because N is at most `0xffffffff`. All three scalar identities are independently proved. The second size formula is `(P+10) mod 2^32` generally, and equals the mathematical sum under that bound [XR5]. No native allocation success is inferred.

The heap object's +0/+8 fields are only established as zero-initialized here; the +20 four-byte region is unknown. A linked-list/tree/container interpretation requires later field writes and consumers. The 16 B object Q and this 32 B allocation remain distinct. SP+`0xa60` receives another 64-bit computed quantity whose full downstream role is unknown; it is not conflated with the proved 32-bit allocation length.

## Result, failure, ports, and unresolved continuations

| Selected condition | Original continuation | Evidence boundary |
|---|---|---|
| Variable discriminator and H=0 | `0x100c8f210` -> `0x100c044d4` | Stores constant `0x8b3dc651` at SP+`0x81c`; publishes Q through the pointer at SP+`0x568` |
| Post-publication branch | Table index `0x893a` -> `0x100c4dc4c` | Same target as the preceding report's failed 16 B allocation branch; final status remains unknown |
| Null Q or rejected helper extent | `0x100c29a88` | Loads saved continuation SP+`0x538`, then branches to its original target `0x1009e1230`; full return ABI remains unknown |
| Either new allocation returns NULL | `0x100c0b788` | Retained cleanup frontier; complete memory effects and successful cleanup are unproved |
| Discriminator/fixed-size rejection | `0x100bd9558` | Retained status/record continuation; not assigned a public error code or final reply |
| Successful buffer allocation | `0x100b067d8` | Further packing/control-flow frontier with additional frame inputs; not a proved serialized result |

In the inherited first-record path, SP+`0x568` contains the address of local SP+`0x898`. Publishing Q through it is a local result write, not an interprocess send or a kernel pointer publication. The shared continuation `0x100c4dc4c` is not sufficient to label every predecessor success or failure. All such outcome claims require its status consumers and later control flow [XR3-XR6].

Only two newly resolved external calls occur in the retained constructor path, both malloc. No new incoming/outgoing Mach name, descriptor, right disposition, XPC reply emission or IOKit call is established here. The copied data pointer, local Q pointer, heap pointers, code pointers, saved peer and audit token are different domains. The next work is to follow `0x100b067d8`, the helper continuation `0x1009e1230`, and result/status consumers at `0x100c4dc4c`, then identify iteration, actual command dispatch, peer/audit use and reply/cleanup behavior. Native service identity and a successful daemon/kext exchange remain unknown [XR6-XR7].

## Assumption register

| ID | Assumption and dependent findings | Stress test / falsification probe |
|---|---|---|
| XR1 | Pinned original daemon and unchanged preceding evidence delimit addresses, frame and copied-input meanings. | Rehash originals/dependencies; recapture every fragment and compare inherited ranges; require native loaded-image/epoch evidence separately. |
| XR2 | Original pointer tables, bank values and ABI-preserved state hold. Calls and branches depend on them. | Exhaust 256 inputs per bank; independently compare current dyld_info fixups and original modifiers; reject altered banks/modifiers. Hardware PAC is untested. |
| XR3 | Selected allocations and source storage are valid/disjoint, and relevant slots are not modified through aliases. Record values and pointer provenance depend on this. | Follow allocation, mutations, escaping aliases, lifetime and cleanup before asserting native validity or ownership balance. Unwritten local +4 and heap +20 regions remain unknown. |
| XR4 | The initial cursor/frame and first-record defaults are inherited exactly from the preceding fitted-record path. | Trace every predecessor and later reset/cursor update. Do not generalize the first-record model or discriminator tree to complete native protocol acceptance. |
| XR5 | W/X widths, modulo arithmetic, signed 16-bit comparisons, unsigned extents and byte order match the retained instructions. | Instruction assertions, exhaustive T model, SDK layout compile and eight scalar queries; reject signedness/endian/width/offset changes. |
| XR6 | Value conversion and local construction are established; H's semantic role, command admission, token use and final response are unknown. | Follow actual H consumers, variable H-zero result, saved helper return, construction and status/reply paths before assigning those meanings. |
| XR7 | Prior trace, kext contracts and native endpoint observations retain their original scope. Current tools expose no knowledge-store search. | Preserve prior evidence; do not infer Mach identity, an IOKit selector or native exchange from internal value tags, shared addresses or local result writes. |

## Bounded additional context

| Impact | Pattern / consequence | Remaining boundary |
|---|---|---|
| High | Three exact discriminator values select fixed BE32, fixed BE64 or a byte reference. | Higher-level schema, H meanings, dispatch and native acceptance are unknown. |
| High | The variable branch's early result is governed by H-zero, independently of P-zero. | Its terminator/result meaning and subsequent caller behavior require downstream evidence. |
| High | Constructor size P+10 has a proved unsigned bound inherited from the outer initial fit. | Complete ownership, all later iterations and memory validity remain unknown. |
| Medium | Local arguments, Q, a 32 B heap allocation and its second buffer are separate representations. | Full container organization, packing, insertion and destruction remain unknown. |
| Medium | Failed allocation and result publication can reach the same continuation. | Address convergence alone does not determine outcome or public error status. |

## Verification and quality gates

The capture retains 25 fragments, 777 instructions/3108 B, two bank cases/512 inputs, two calls, 33 branch bindings, one import and 30 selected pointers. Independent current dyld_info output matches all 61737 fixup memberships and every selected line. Checks pass 61 instruction assertions, 15 SDK assertions/one compilation, eight unsatisfiable scalar queries, all 65536 discriminator patterns, four variable-condition Boolean cases and eight rejected evidence alterations. No recovered machine code executes or is emulated, no native target request is sent, and no IDB/service state is modified.

Capture/verification costs O(B+F+I+256K+65536) time and O(B+F+I+256K+65536) space, including the retained two-byte-per-input routing digest buffer; B=image bytes, F=fixups, I=instructions, K=bank cases. SDK compilation and solver costs are separate; queries each have a 10 s timeout. The selected header/value conversion and constructor-prefix work are O(1) per record, excluding allocator and unresolved downstream buffer processing. Publication/audit costs O(total artifact bytes + local links). Extents and allocation sizes use B throughout.

QG1: Factual binary interface analysis requires no normative premise.

QG2: XR1-XR7 specify assumptions, dependent results and falsification probes.

QG3: The initial fitted header, all discriminator values, fixed/variable branches, local layout, selected allocations and result/continuation sites are covered; the full interface goal remains active.

QG4: Signed16 routing, BE32/BE64 conversion, XOR encodings, byte extents, allocation bound and reconstructed layouts are explicit and checked.

QG5: H versus P, H-zero versus zero extent, first-record versus later defaults, local result versus IPC, shared continuation versus final status, and local/heap/Q representations remain distinct. Unwritten regions and unproved cleanup remain explicit.

QG6: Original instructions, exact malloc binding, current independently refreshed fixups, SDK/tool hashes, retained queries and exhaustive scalar models provide provenance. Native behavior and unavailable memory-store recall are not fabricated.

QG7: Impact-labeled discriminator, H-zero, extent, representation and convergence observations are bounded above; no native exchange, complete dispatch/reply recovery or full-goal completion is claimed.
