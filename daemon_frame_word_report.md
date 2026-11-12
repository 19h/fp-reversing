# Daemon frame word: conditional definition and retained ingress frontier

Subsequent admission evidence: the [frame-admission report](daemon_frame_admission_report.md) recovers the unsigned n < (word XOR 0x8b3dc651) gate, its object-word lineage and the opposite branch's frame+0x4ec remainder writer. The four actual partial paths have n=0 and decoded word28, so they reach the reader without this writer. Eleven source obligations and136 A64 replays support the stated conditional contracts; native admission and the unresolved frame inputs remain unknown.

The source contains a conditional definition for the word read at root-frame F+0x560. With phase0x871a and the original dispatch-table root, `0x1003fd1d8` loads u32[F+0x4ec], dispatches to `0x100530720`, and stores that value at F+0x560. The writer compares it with u32[F+0x3c4]. Its unsigned less-than outcome reaches the previously unresolved reader `0x10063735c` through `0x100523774`. Thus a source-defined producer-to-consumer route exists. Its upstream admission and F+0x4ec producer remain unknown.

The four retained prefix/extended ingress paths use a different predecessor. They write F+0x55c=0 and F+0x3c4=12, then reach the same reader without writing F+0x560. Those paths remain stopped before arithmetic at `0x10063736c`; the newly found producer is not spliced into them. This increment establishes a conditional data/control contract, not a native uninitialized read or a completed IOKit transaction. The full interface investigation remains active.

Primary evidence: [source/proof/control producer](triage_evidence/recover_daemon_frame_word.py), [retained evidence](triage_evidence/daemon_frame_word_checks.json.zst), [independent auditor](triage_evidence/audit_daemon_frame_word.py), [A64 controls and frontier audit](triage_evidence/daemon_frame_word_audit.json.zst), [publication verifier](triage_evidence/verify_daemon_frame_word_publication.py). Parent evidence: [source ingress](daemon_versioned_ingress_report.md), [root lifecycle](daemon_versioned_root_report.md), [versioned ABI](versioned_request_abi_report.md), [Mach index](mach_ports_report.md). Original daemon SHA-256: `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.

Preferred image base is0x100000000. F denotes the root's post-prologue SP, B denotes bytes, and all u32 arithmetic wraps modulo2^32. Names such as value, limit and companion describe local operations; public protocol meanings are unknown.

| Assumption | Dependent results | Stress test / falsification probe |
|---|---|---|
| FW1 | Original image, sixteen parent receipts and nineteen source dependencies identify this analysis. | Rehash inputs, source regions, used original fixups and every rechecked parent opcode; reproduce the producer and audit. |
| FW2 | In the four retained partial cases, F=callerSP-0x9d0. | Parent interface audit independently derives the adapter temporary and root frame; compare the recovered reader address and byte origins. A different adapter reserve requires a new frame calculation. |
| FW3 | The new producer route begins at an interior source slice with phase0x871a and X23 equal to the original table root. | Source proofs and relocated A64 controls check the complete selected edge chain. A composed upstream path is required to establish actual admission. |
| FW4 | Symbolic frame cells and table cells are disjoint, with no address wrapping or aliasing between declared cells. | Retain source queries; concrete controls use two disjoint frame/owner layouts. An aliasing frame requires a separate domain. |
| FW5 | Private controls declare F+0x4ec, F+0x3c4, F+0x380, F+0x2a0 and the companion register. PAC branches are logical transfers through original resolved fixups. | Check every original instruction, register, flag, memory event, target and modifier with an independent A64 engine; no native authentication or object ownership follows. |
| FW6 | The store census covers its explicit A64 immediate forms in aligned original __text. A shared displacement does not identify a shared frame. | Independently decode candidate widths/displacements; retain section hash, all candidates and metadata envelopes. Register-offset stores, aliases, other store families/regions and SP epochs require further analysis. |
| FW7 | Actual partial-path evidence comes from pinned parent journals; their earlier independent CPU replays are retained, not repeated here. | Recheck191598 original visits and all overlapping writes; compare parent interface joins and exact unknown-byte origins. A native capture could test the upstream lifetime premise. |
| FW8 | The reader transformation is a local representation operation. Public field schema, status meaning and transport exposure remain unknown. | Trace upstream values and downstream uses before assigning protocol names or correlating native IPC/IOKit events. |

```text
conditional source route [FW3-FW5]
  0x1003fd1d8: phase0x871a; a=u32[F+0x4ec]
       |
  0x100530720: [F+0x560]=a; [F+0x564]=companion
       |
       +-- a >= u32[F+0x3c4] --> 0x100537880 [stop before entry]
       |
       +-- a <  u32[F+0x3c4] --> 0x100523774
                                         |
                                  [F+0x528]=[F+0x380]
                                         |
retained partial route [FW2,FW7]          |
  0x10063ac7c: [F+0x55c]=0               |
              [F+0x3c4]=12               |
       |                                 |
  0x1004712f4: [F+0x508]=[F+0x380]       |
       |                                 |
       +----------------+----------------+
                        |
                 0x10063735c
                 phase0x871a -> 0x8554
                 read u32[F+0x560]
                        |
       conditional controls: add0x2f95a328 -> [F+0x258]
       retained partials: STOP before this ADD; value unspecified
```

| Original source edge | Table index | Original slot | Destination | IA modifier |
|---|---|---|---|---|
| 0x1003fd204, phase0x871a | 0x6fb1 | 0x101071c78 | 0x100530720 | 0xc4d3 |
| 0x100530778, a >= limit | 0xa866 | 0x10108e220 | 0x100537880 | 0x1ff5 |
| 0x100530778, a < limit | 0xa8b4 | 0x10108e490 | 0x100523774 | 0x1ff5 |
| 0x1005237d4, less-than route | 0x4a7f | 0x10105f2e8 | 0x10063735c | 0xa50a |
| 0x100471358, retained partial route | 0x4a7f | 0x10105f2e8 | 0x10063735c | 0xa50a |

These mappings use source table loads and original fixup records, rather than modifier equality alone. The writer also has an original pointer at slot0x10107d360 with IA0x29a0. That pointer is retained as an additional candidate ingress; its actual incoming site/context is unknown. Slot0x10103f138 points to the new predecessor0x1003fd1d8 with IA0x5edb, without establishing its upstream producer.

| Source location | Incoming data | Outgoing contract | Established scope |
|---|---|---|---|
| 0x1003fd1f8 | u32[F+0x4ec] | W20=a | Conditional slice, not an established F+0x4ec writer. |
| 0x100530744 | W11 | u32[F+0x564]=companion | Arbitrary u32 companion; later role unknown. |
| 0x100530748 | W20=a | u32[F+0x560]=a | Source definition on the conditional route. |
| 0x10053074c..0x10053076c | a, u32[F+0x3c4] | Unsigned comparison selects indices0xa8b4/0xa866 | Equality selects0xa866. Signed ordering is not used. |
| 0x100523780 | u64[F+0x380] | u64[F+0x528] receives the same value | Pointer-shaped copy; no native ownership claim. |
| 0x10063ac9c,0x10063aca0 | W12,W10 | u32[F+0x55c],u32[F+0x3c4] | Values0,12 in all four retained partial cases. |
| 0x100471308 | u64[F+0x380] | u64[F+0x508] receives the same value | Alternate-route copy; distinct from F+0x528. |
| 0x100637368..0x100637370 | u32[F+0x560]=a | u32[F+0x258]=u32(a+0x2f95a328) | Executed only in source-defined controls; partial ingress still stops before ADD. |

The predecessor produces W10=0xa866 while dispatching through X8, so it preserves the writer's phase input. The writer produces W8=0x0a25 and W9=0x2fa3. The less-than continuation turns W9 into0x871a and selects the reader's index0x4a7f. The alternate predecessor also reaches the reader with W9=0x871a. The first reader instruction subtracts0x1c6. Ten fresh source queries are UNSAT and cover these phase/index equations, both stored words, original table outcomes, field copies and the reader transformation [FW3-FW5].

The scoped store census finds47 unsigned-immediate SP stores overlapping bytes+0x560..+0x563:25 u32 stores and22 u64 stores. It finds no overlapping Q-register pair stores in the included forms. Every candidate is retained with original opcode, displacement, width and LC_FUNCTION_STARTS envelope. Those metadata envelopes differ across the new chain and do not partition its semantic control flow. No candidate is globally assigned to the root from its displacement [FW6].

For each of two epochs, controls cover (a,limit)=(0,12),(1,12),(11,12),(12,12),(13,12),(0xffffffff,12),(0x80000000,0xffffffff),(0xffffffff,0xffffffff),(0,0),(0xfffffffe,0xffffffff). Companion values cycle through0,0x2a15b77c,0xdeadbeef. Ten less-than cases execute66 visits each through the reader store; ten other cases execute35 visits each and stop before0x100537880. Unsigned high-bit and equality cases distinguish ordering from signed comparisons. These are declared source-local controls, not accepted protocol records or continuations of the actual partial fixtures [FW5].

Independent original-A64 replay checks1010 visits,32320 register values,1010 NZCV values,760 read B,280 written B and50 logical PAC transfers. Six source regions retain148 instructions/592 B. The independent census uses explicit instruction classes and decoded operand widths, rather than the producer's width arithmetic. The four parent partial cases contribute191598 opcode rechecks and preserve the exact four unknown-byte origins at F+0x560. No overlapping prior write or visit to the new writer occurs in those cases [FW7].

The conditional route establishes one definition and a subsequent use; it does not establish a definition dominating all reader entries. F+0x4ec, the companion register and the route's upstream admission still need producers. Other reader inputs, including F+0x538 and F+0x5c8, retain their earlier unknown contracts. A chosen value for F+0x560 would not establish the complete input context. No native defect follows from a deliberately incomplete private entry state.

No incoming/outgoing Mach port, descriptor/right producer or message-emission location is added. The source controls contain no call instruction or external API model. Neither the IOKit call0x100478a04 nor a kext routine is executed. Complete buffer identity, connection provenance and native daemon/kext pairing remain unknown. Original image instructions, data/fixup bytes and pinned local receipts provide provenance; no matching live-IDB observation is asserted.

| Bounded continuation | Impact | Falsifiable completion criterion |
|---|---|---|
| Establish admission to0x1003fd1d8 and F+0x4ec's producer. | High | Compose actual incoming dispatch, value writers and a coherent frame lifetime; a pointer or modifier match alone is insufficient. |
| Establish whether the alternate route requires an earlier F+0x560 definition. | High | Recover a dominating source write or justified input/environment contract for a complete admitted path. |
| Recover the reader's remaining frame inputs. | High | Establish producers and extents for F+0x538, F+0x5c8 and the other consumed cells before extending execution. |
| Resolve the writer's IA0x29a0 ingress. | Medium | Prove actual table materialization, preserved phase and compatible frame, without assigning callers from the modifier alone. |
| Correlate the preparation with transport. | High | Establish the complete buffer and connection lifetimes and match actual method/message events to compatible source identities. |

Quality gates for this bounded increment:

- **QG1**: Factual technical analysis requires no normative premise.
- **QG2**: FW1-FW8 state assumptions, dependent results and falsification probes.
- **QG3**: Conditional producer, consumer, table edges, data/control flow, environmental premises and IPC limits are covered; the larger goal remains active.
- **QG4**: U32 modular values, byte extents, instruction visits, register/flag checks and retained-parent checks are distinct and reproducible.
- **QG5**: Conditional source definitions are separated from actual partial entries, unspecified bytes, native admission, other frames and metadata envelopes.
- **QG6**: Original source/fixup bytes, hashes, fresh source queries and independent A64 effects support the claims; native APIs/PAC and matching live-IDB evidence remain unknown.
- **QG7**: The continuation table bounds and ranks admission, data definitions, remaining inputs, candidate ingress and transport correlation.
