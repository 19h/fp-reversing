# fairplayd: tag-selected scalar loop, coordinate output and status return

Raw tag `0x76657273` (`vers` in big-endian ASCII) selects the previously recovered byte-to-packed-scalar loop. Its gate at `0x1009a1574` compares a u64 count against a zero-extended u32 index; its back edge reloads the saved index/count and increments the index modulo 2^32. With the earlier decoded u32 count preserved and each body reaching that back edge, the loop executes exactly C iterations, including zero iterations for C=0. This is a conditional control-flow bound; arbitrary body termination and memory admission remain unknown. [CL1-CL6; CL-A1-CL-A5]

On the eight retained successful branch classes, C=4 and the gate indices are 0,1,2,3,4. Completion writes raw coordinate `0x76d8ea95` to optional output D=`SP+0xd98`, restores nested raw status `0x8b3dc651`, reverses the private 32 B cursor advance and reaches the outer equality successor `0x1008a2610`. The coordinate decodes to byte offset 21 under the prior coordinate codec. This closes the immediate caller's output/status handoff; native caller/root/cache epochs, parent J+0x68 publication and daemon-kext transaction identity remain unknown. [CL1-CL6; CL-A1-CL-A6]

| Evidence | Primary provenance and scope |
| --- | --- |
| CL1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; CL4 retains 161 original instructions in twelve spans and thirteen original format-12 dispatch words. |
| CL2 | [Child payload](daemon_child_payload_report.md): decoded-count origin, byte decoder, four scalar fields and input/output custody. [Child operation](daemon_child_operation_report.md): inherited caller fields, private cursor advance and saved outer continuation. Exact checks/audit hashes are pinned in CL4. |
| CL3 | [Constructor buffers](daemon_constructor_buffer_report.md), [record spans](daemon_record_spans_report.md) and [coordinate selection](daemon_record_selection_report.md): prior conditional admissions, field/coordinate codecs and retained branch classes. Complete prior admissions are not rerun. |
| CL4 | [Extractor](triage_evidence/recover_daemon_child_loop.py), [checks](triage_evidence/daemon_child_loop_checks.json.zst): 152 selected slices, eight loop sequences, eighty fresh read/last-writer links and 32 explicitly inherited field checks. |
| CL5 | [Auditor](triage_evidence/audit_daemon_child_loop.py), [receipt](triage_evidence/daemon_child_loop_audit.json.zst): seventeen nonvacuous UNSAT obligations, twenty scalar controls and independent instruction/register/flag/memory/edge replay. No proof cuts. |
| CL6 | [Publication verifier](triage_evidence/verify_daemon_child_loop_publication.py): fresh extraction/audit, canonical SMT comparison, exact manifest delta, original-input preservation and decoded path hygiene. |

## Tag routing and counted loop

Address arithmetic is u64 modulo 2^64; scalar/index arithmetic is u32 modulo 2^32. B denotes bytes. SP is the private frame base used by the retained model. CL2's setup decodes the count with XOR `0x8b3dc651`, zero-extends the result and saves it at SP+0x7df8. The loop gate itself makes an unsigned 64-bit comparison; it does not truncate that saved count. [CL1-CL5; CL-A1-CL-A4]

| Source block | Fixed entry phase / input | Established local contract |
| --- | --- | --- |
| `0x1008ef9f4` | W13=`0x82e2`, arbitrary raw tag W12 | Signed tag < `0x76657273` selects index `0x82f6`; otherwise `0x82e2`. W16 becomes `0x3fa5`. |
| `0x100a3811c` | W16=`0x3fa5`, arbitrary raw tag W12 | W15 becomes zero, W14 becomes `0x1e5c`; exact `vers` selects `0x68d9`, mismatch `0x3fa5`. |
| `0x1009a1574` | W14=`0x1e5c`, index W15=i, count X19=C64 | Save i at SP+0x4f6c; X10=zero_extend64(i). C64>X10 selects body index `0x6a7e`, otherwise exit `0x1e5c`. W8=`0x97a`, W12=`0x6cf4`. |
| `0x100957a58` | Saved phase SP+0x9d0=`0x6cf4` | Reload i from SP+0x4f6c, reload C64 from SP+0x7df8, set W15=u32(i+1), reconstruct W14=`0x1e5c` and branch through `0x68d9` to the gate. |

The initial signed partition is distinct from the unsigned count gate. In particular, a raw tag with bit31 set is signed-negative at the partition. Exact `vers` passes both tag tests. The ASCII spelling establishes a selector literal; the payload's public schema and conventional version-number interpretation remain unknown. Other tag handlers are not exhaustively classified by this increment. [CL1, CL4-CL5; CL-A1-CL-A2,CL-A6]

```text
tag == vers -> i32 = 0
                   |
                   v
        save i; compare C64 > zero_extend64(i32)
             | true                       | false
             v                            v
   byte decoder / packed writer      optional coordinate output
             |                            |
   normal body reaches back edge          v
             |                     restore raw nested status
   reload saved i and C64                   |
   i32 = u32(i32+1)                        v
             +----> gate            shared tag/mask postprocess
```

For C=zero_extend64(c32), let r=c-i in widened unsigned arithmetic. Under i<c, i is at most `0xfffffffe`, so the source increment does not wrap, i+1<=c, and r decreases by one. Initialization gives i=0; the gate exits at i=c. Therefore, if every active body returns to the back edge with its saved index/count definitions intact, exactly c bodies occur. The maximum arithmetic iteration count is 2^32-1. No wall-time, native-instruction or complete arbitrary-body termination bound follows. [CL2, CL4-CL5; CL-A2-CL-A5]

The u32 count domain is necessary. A separate universal obligation shows that any C64>`0xffffffff` exceeds every zero-extended u32 index. The scalar boundary control C64=`0x100000000`, i=`0xffffffff` selects the body and increments to zero if the body returns. This is an excluded source-domain control, not an observed target state or evidence of a reachable failure. CL2's count decoder and CL4's retained custody satisfy the narrower count premise. [CL2, CL4-CL5; CL-A2-CL-A5]

Fresh custody checks identify every one of the 32 retained back-edge index reads with the corresponding gate store at `0x1009a1584`. All 32 count reloads have last writer `0x1007579f4`. The observed four back edges produce next indices 1,2,3,4; the fifth gate exits. This closes the counted envelope around the earlier byte decoder and four actual packed payload fields at buffer offsets 41,45,49,53 B. Input readability, destination capacity and arbitrary-body normal return still require their own admissions; the counter theorem supplies none of them. [CL2-CL5; CL-A2-CL-A5]

## Optional coordinate output and restored status

| Field / role | Width | Source and custody | Retained value |
| --- | --- | --- | --- |
| SP+0xd80: D | 8 B | Inherited caller field; loaded at `0x1008d34a0` | SP+0xd98 |
| SP+0x816c: encoded record coordinate | 4 B | Actual writer `0x10069e92c`; read at `0x10076d5dc` | `0x76d8ea95` |
| D: optional coordinate result | 4 B | Copy store `0x10076d5e0` | Little-endian bytes `95 ea d8 76` |
| SP+0x8d8c: raw nested status | 4 B | Store `0x100751f2c`; restore `0x1006d143c` | `0x8b3dc651` |
| SP+0x2090: raw caller tag | 4 B | Inherited caller field; loaded at `0x1006d1440` | `0x76657273` |
| SP+0x8b90: saved frame return | 8 B | Inherited caller field; loaded at `0x100924864` | `0x1008c25f4` |
| SP+0x3980: saved outer return | 8 B | Inherited caller field; loaded at `0x1008c25f4` | `0x10072c448` |

At exit phase W12=`0x6cf4`, block `0x1008d3490` tests D. Non-NULL selects `0x10076d5d8`, which copies the four-byte encoded coordinate from SP+0x816c to D. NULL skips that copy. Both paths select `0x1006d140c`, with W8=`0x4045` and X12=SP+0x8000. The retained cases all have non-NULL D; the NULL case is a universal source equation without an execution witness. Destination accessibility and separation from subsequently read caller/table fields remain admission premises. [CL1-CL5; CL-A2-CL-A5]

The prior coordinate codec is `offset_B=u32(q+0x89271580)`. For q=`0x76d8ea95`, the widened sum is `0x100000015`; reduction modulo 2^32 gives `0x15`=21 B. The source copies q, not the decoded byte offset and not W27. These are separate ABI outputs. Eight fresh coordinate links identify `0x10069e92c` as the actual last writer; eight status links identify `0x100751f2c`. Merely equal numeric values are not used to infer this custody. [CL2-CL5; CL-A1-CL-A4]

Block `0x1006d140c` loads U from SP+0x42e0, reads U+0x28, restores W27 from SP+0x8d8c and reads the saved tag. Its `CCMP` predicate selects index `0x8aae` exactly when mask4 is clear and tag=`0x69746772` (`itgr` in big-endian ASCII). Otherwise it selects `0x4045`. All four NZCV outputs are proved against conditional subtraction or the zero fallback. The further-work target `0x100705fb8` remains unclassified here; the literal alone does not establish its semantic function. Exact `vers` cannot satisfy that predicate under any flag value. [CL1, CL4-CL5; CL-A1-CL-A2,CL-A6]

```text
saved raw status -> SP+0x8d8c -> restore W27 at 0x1006d143c
                                      |
clear mask4 AND tag == itgr -----------+--> 0x100705fb8 (further work unknown)
otherwise                             |
                                      v
0x100924854: private cursor -= 32 B; preserve W27
  -> saved 0x1008c25f4, IA 0x8eb3
  -> saved 0x10072c448, IA 0x9325
  -> W27 == 0x8b3dc651 ?
       yes: 0x1008a2610       no: 0x1006ad0a8
```

Universal source equations preserve arbitrary restored W27 through both standard return blocks and prove the outer equality decision. In all eight retained classes the restored word is `0x8b3dc651`, so the recorded successor is `0x1008a2610`. This is the caller's exact local equality criterion; it does not identify a general operating-system success code. The subsequent parent/context update and native caller epoch remain unknown. [CL2, CL4-CL5; CL-A2-CL-A6]

## Original dispatch mappings

| Index32 | Target | IA modifier |
| --- | --- | --- |
| `0x82e2` | `0x100a3811c` | `0xd40d` |
| `0x82f6` | `0x100753528` | `0xd40d` |
| `0x3fa5` | `0x10083923c` | `0x987b` |
| `0x68d9` | `0x1009a1574` | `0x987b` |
| `0x6a7e` | `0x1008f0c14` | `0x1d3b` |
| `0x1e5c` | `0x1008d3490` | `0x1d3b` |
| `0x3f00` | `0x1006d140c` | `0x5a94` |
| `0x3f0d` | `0x10076d5d8` | `0x5a94` |
| `0x4045` | `0x100924854` | `0x5469` |
| `0x8aae` | `0x100705fb8` | `0x5469` |
| `0xf29` | `0x1008c25f4` | `0x8eb3` |
| `0x8eff` | `0x1008a2610` | `0xb0c4` |
| `0x8e61` | `0x1006ad0a8` | `0xb0c4` |

Original pointer words establish target, IA diversity and address-diversity-0 fields. The outer return to `0x10072c448` additionally uses the inherited saved pointer with IA diversity `0x9325`. Selected transfers are checked against their actual next retained PC and modifier. Hardware PAC, concurrent pointer changes and native lifetime are not established. No new incoming/outgoing Mach port, right transfer or emission location is established by these private loop/output/status blocks. Existing [port findings](mach_ports_report.md) remain the transport evidence boundary. [CL1-CL6; CL-A1,CL-A3-CL-A6]

## Validation, assumption register and bounded continuation

Independent replay covers 152 slices, 2,296 original instruction visits, 78,336 GP/SP values, 78,336 Q values, 2,448 NZCV frames, 424 reads, 72 writes and 136 logical authenticated transfers. Seventeen nonvacuous UNSAT obligations establish tag selection, loop update/ranking/domain limits, output/status copies, complete conditional-compare flags, return/cursor behavior and the outer result gate. Twenty scalar controls exercise tag/mask combinations and count boundaries. Eight retained loop sequences and eighty fresh custody links connect these local source contracts. [CL4-CL6]

Extraction uses O(parent bytes + retained events + custody scans) time/space. Selected replay costs O(visits*32 + byte events); source lifting adds the expression-DAG size and solver search, with a 30 s timeout per query. In a complete admitted loop, the control envelope is O(C) and its counter state is O(1); body cost and memory footprint remain separate. Archives use zstd with decoded round-trip checks. Existing references suffice; IDA is not accessed and no native target API, IPC, allocation, free or hardware authentication is executed. [CL1-CL6; CL-A1-CL-A5]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CL-A1: Exact pinned image, original fixups and parent receipts apply | Opcodes, constants, source equations and prior codecs | Rehash source/parents; compare original instruction and dispatch words; regenerate extraction/audit and canonical SMT. |
| CL-A2: Fixed entry phases and prior conditional admissions apply | Eight loop/output/status classes; caller-field identities | Replay selected GP/SP/Q/NZCV and memory events; retain each class's earlier API/root/owner premises. No alternative/native admission is inferred. |
| CL-A3: Sequential, coherent, separated memory and inherited caller definitions apply | Saved count/index, optional output, status and continuation custody | Check exact current last writers and inherited-byte identities; falsify with overlaps, changed definitions or native epoch evidence. D must remain compatible with subsequent caller/table reads. |
| CL-A4: Logical authentication models the recorded dispatch | Returned pointers, original route words and ordering | Compare next PCs and modifiers; require distinct native PAC, scheduling and lifetime evidence. |
| CL-A5: Count remains decoded u32 and every active body reaches its back edge with saved definitions intact | Exactly C arithmetic iterations and no active increment wrap | Prove widened rank decrease; test C=0,1,4,2^32-1 and excluded C64=2^32. Full body termination, memory admission and time bounds remain unknown. |
| CL-A6: Local tag/coordinate/status contracts do not establish public schema or transport identity | `vers`/`itgr` interpretation and daemon-kext conclusions | Require independent consumers, parent publication and matched Mach/IOKit transaction/buffer bytes. |

| Impact | Bounded next evidence | Present limitation / falsification target |
| --- | --- | --- |
| High | Follow equality successor `0x1008a2610` to parent/context publication | Exact nested-to-outer handoff is established; J+0x68 publication and native epoch remain unknown. |
| High | Join the tagged scalar record to daemon Mach/IOKit requests and kext consumers | No new port/right/emission or paired transaction is established here. |
| High | Close the alternative storage mode's validation and packed-writing admission | Both mode predicates are known; the complete alternative execution remains unobserved. |
| Medium | Resolve `itgr` further-work target and independent tag consumers | Shared predicate is exact; handler meaning, full tag taxonomy and public schema remain unknown. |
| Medium | Compose arbitrary-byte packed writing with complete body return and range premises | Per-byte decoder and control envelope are known; arbitrary arrays and native performance are not established. |

**QG1**: factual control/data-flow and ABI analysis. **QG2**: CL-A1-CL-A6 list dependent results and falsification probes. **QG3**: this loop/output/status increment is covered; the full interface investigation remains active. **QG4**: widths, byte units, modular arithmetic, ranking, counts and complexity are explicit. **QG5**: signed tag comparison, unsigned count gate, u32 domain, raw coordinate/status and body-admission limits are distinct. **QG6**: delivery requires fresh verification against pinned primary artifacts. **QG7**: impact-labeled adjacent interfaces and unknowns are enumerated.

## Record-extension follow-up

The [record-extension increment](daemon_record_extension_report.md) continues the broader growth-success corpus through five declared fresh allocation returns and reaches the local J+0x68 publisher. A later itgr invocation stops before the shared postprocessing gate on an undefined SP+0x390 pointer; it is not an execution witness for the clear-mask further-work route. Native epoch and transport identity remain unknown.

## Record-bank follow-up

The [record-bank increment](daemon_record_banks_report.md) establishes a separate descending masked-byte loop in the retained itgr context. Its post-store zero-index route selects the same optional output/status block as the earlier vers loop. Direct zero-count entry wraps in this prefix and is excluded from its positive-count theorem; no current execution of the shared completion or further-work route is claimed.
