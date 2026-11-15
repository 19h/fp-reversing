# fairplayd: child-operation token, U guards and result continuation

The caller boundary at `0x100762e48` constructs raw bytes `98 99 98 99` in a four-byte private record, reloads the saved U/result-pointer pair, and prepares raw tag `0x76657273`. The following operation requires non-NULL U, at least one non-NULL base, flag bit 0 clear and flag bit 1 set. Both published flags `0xd299e642` and `0xd299e646` satisfy these two guards; mask4 does not select this prelude. The retained clear route reaches the already documented constructor validation boundary. The alternative route has source contracts but no execution witness. [CO1-CO6; CO-A1-CO-A6]

The saved outer result continuation at `0x10072c448` compares raw W27 with exactly `0x8b3dc651`. Equality selects `0x1008a2610`; inequality selects `0x1006ad0a8`. The earlier constructor's odd/even W8 return and this raw W27 status are distinct interfaces. No new Mach-port emission, native caller/cache epoch or daemon-kext transaction pairing is established. [CO1, CO4-CO6; CO-A2-CO-A6]

| Evidence | Primary provenance and scope |
| --- | --- |
| CO1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; 264 instruction words in 13 spans, with 16 original authenticated pointer words retained in CO4. |
| CO2 | [Alternative header/caller](daemon_alternative_header_report.md) and [conditional clear initializer](daemon_constructor_gate_report.md). Exact checks/audits are pinned in CO4. Four representative clear intervals cover the inherited 76-parent cohort under their earlier admission premises. Those admissions are not rerun here. |
| CO3 | [Constructor-buffer validation](daemon_constructor_buffer_report.md), [constructor descriptor/root provenance](daemon_constructor_descriptor_report.md) and [storage selector](daemon_storage_flag_report.md). These establish separate downstream contracts and distinguish root premises from native continuity. |
| CO4 | [Extractor](triage_evidence/recover_daemon_child_operation.py), [checks](triage_evidence/daemon_child_operation_checks.json.zst): original source/fixups, 36 selected slices, four retained views and 32 saved-cell checks. |
| CO5 | [Auditor](triage_evidence/audit_daemon_child_operation.py), [receipt](triage_evidence/daemon_child_operation_audit.json.zst): 18 nonvacuous UNSAT queries, eight scalar controls and independent source/frame/event/edge replay. No proof cuts. |
| CO6 | [Publication verifier](triage_evidence/verify_daemon_child_operation_publication.py): fresh extraction/audit, canonical SMT comparison, exact manifest delta, original-input preservation and decoded path hygiene. |

## Private token and operation inputs

All scalar arithmetic is u32 modulo 2^32; pointer arithmetic is u64 modulo 2^64. All offsets and extents denote bytes (B). SP is the unchanged outer private-frame base, not a recovered native stack placement. Source equations quantify arbitrary pointers, coordinate32, payload32, cursor64, flags32 and status32 under the stated source phase and valid separated memory. [CO1-CO6; CO-A1-CO-A4]

`0x100762e48` rebuilds W25=`0x6cf4` from W28=`0x155f` and prepares token pointer SP+0x5378. `0x1009679f0` supplies the writer constants and sets X24=(SP+0x9e0) XOR `0xc00e63b366f327e4`. The use and native lifetime of that descriptor are not established by this increment. [CO1, CO4-CO5; CO-A2-CO-A4]

For input W8=u32(o+`0x237c979d`) and arbitrary payload P32, writer `0x10077b08c` has this universal four-byte contract:

```text
for j = 0..3:
    byte[base + zero_extend64(u32(o+j))] = BE_byte(P XOR 0xec2d0e54, j)
```

The four byte-address and value equations are proved independently for all inputs. The recovered immediate call has o=0, P=`0x74b496cd`, base=SP+0x5378. Thus P XOR `0xec2d0e54`=`0x98999899`, giving raw bytes `98 99 98 99`. The corresponding little-endian u32 is `0x99989998`. These exact raw bytes alone do not establish a decoded payload schema. Generic o may wrap in u32; the source equation uses zero extension separately for each address. [CO4-CO5; CO-A1-CO-A4]

The writer dispatches to `0x1007948e4`, IA diversity `0x6878`, while preparing X12=SP+0xa698 and X13=SP+0xa0a0. The reload block obtains U from SP+0xaf18 and destination D from SP+0xaf20. The earlier caller prepares D=SP+0xd98, conditional on matching caller/private-frame epochs. [CO2, CO4-CO5; CO-A2-CO-A4]

| Saved operation field | Width | Source value | Original store |
| --- | --- | --- | --- |
| SP+0x8b90 | 8 B | Outer-return bridge `0x1008c25f4` | `0x100746494` |
| SP+0x2d64 | 4 B | Raw coordinate/operand `0x76d8ea80` | `0x100746498` |
| SP+0x2090 | 4 B | Raw tag `0x76657273` | `0x10074649c` |
| SP+0x2690 | 4 B | Raw word `0x8b3dc655` | `0x1007464a0` |
| SP+0xd80 | 8 B | Destination D | `0x1007464a4` |
| SP+0x4e08 | 8 B | SP+0xc070+incoming cursor | `0x1007464b8` |
| SP+0x16d0 | 8 B | Incoming cursor+32 B | `0x1007464d0` |
| SP+0x4450 | 8 B | Token pointer SP+0x5378 | `0x1007464d4` |
| SP+0x42e0 | 8 B | U | `0x1007464d8` |

The tag's big-endian ASCII spelling is `vers`; its raw little-endian store bytes are `73 72 65 76`. A version-related conventional name is a candidate, not an established operation identity, wire order or public schema. The saved coordinate is one less than the earlier E=`0x76d8ea81`, but that numeric relation alone does not establish a semantic coordinate conversion at this boundary. [CO2-CO5; CO-A2-CO-A6]

## Base and flag guards

```text
saved U/D pair
  -> raw token + operation fields; private cursor += 32 B
  -> U == NULL --------------------------> frame return
  -> U+0 != NULL ------------------------> flag guards
  -> U+0 == NULL -> U+8 == NULL ----------> frame return
                 -> U+8 != NULL ---------> flag guards
  -> flag bit0 set ----------------------> frame return
  -> flag bit0 clear -> flag bit1 clear -> frame return
                    -> flag bit1 set ---> 0x1005f1484
                                          -> pending SP+0x260 read
```

| Gate source | Required condition to proceed | Failure raw W27 | Successful next block |
| --- | --- | --- | --- |
| `0x1007464dc` | U != 0 | `0x74c29d88` | `0x100532e14` |
| `0x100532e34`, `0x100528100` | U[0] != 0 OR U[8] != 0 | `0x74c29d88` | `0x1004e384c` |
| `0x1004e385c` | (U[0x28] AND 1) = 0 | `0x74c29d4b` | `0x10058c6e8` |
| `0x10058c700` | (U[0x28] AND 2) != 0 | `0x74c29d48` | `0x1005f1484` |

The source tests support this low-two-bit interpretation without assigning semantic flag names. Bit2/mask4 and every higher bit are absent from these two guard decisions. All eight low-three-bit scalar controls agree: only 2 and 6 pass both guards. These controls do not create target bytes or establish native acceptance. [CO4-CO5; CO-A2-CO-A5]

The clear source contract has U+0=0, U+8=T!=0, flag `0xd299e642`. The alternative publication contract has U+0=B!=0, U+8=0, flag `0xd299e646`, conditional on successful allocation and its earlier premises. Each satisfies the respective base/flag equations. Four retained clear views reach `0x1005f149c`; all eight bytes of SP+0x260 remain undefined there. This increment does not supply that root. The constructor-buffer report separately supplies an explicit conditional root and follows validation through `0x10057f5ec -> 0x10045f984`; its native join and complete conventional operation name remain unknown. [CO2-CO5; CO-A2-CO-A6]

## Return and exact raw result interface

At `0x100924854`, the frame return subtracts 32 B from SP+0x16d0, loads SP+0x8b90 and branches with IA diversity `0x8eb3`. W27 is preserved. Under matching saved fields and cursor epoch, this reverses the prelude's cursor advance. The recovered saved target is `0x1008c25f4`, which loads SP+0x3980 and branches with IA diversity `0x9325`, again preserving W27. The earlier caller saves `0x10072c448` at that field. [CO2, CO4-CO5; CO-A2-CO-A4]

| Raw status at `0x10072c448` | Dispatch index | Target | IA diversity |
| --- | --- | --- | --- |
| W27 = `0x8b3dc651` | `0x8eff` | `0x1008a2610` | `0xb0c4` |
| Every other u32 W27 | `0x8e61` | `0x1006ad0a8` | `0xb0c4` |

Consequently all three guard-failure words above select the inequality route if returned to this continuation. Equality is a local dispatch classification, not proof of external success. The equality target's later work is outside the new equations. Parent/context publication at J+0x68 and native transport identity remain unknown. [CO1-CO6; CO-A2-CO-A6]

## Original authenticated pointer mapping

| Index32 | Target | IA modifier |
| --- | --- | --- |
| `0x192e` | `0x1009679f0` | `0xbe0b` |
| `0x7a4e` | `0x10077b08c` | `0xe70e` |
| `0x155f` | `0x1007948e4` | `0x6878` |
| `0x291c` | `0x100746474` | `0x7da4` |
| `0xf29` | `0x1008c25f4` | `0x8eb3` |
| `0x403e` | `0x100532e14` | `0x5469` |
| `0x4045` | `0x100924854` | `0x5469` |
| `0x2a9e` | `0x1004e384c` | `0x696a` |
| `0xae23` | `0x1005280e4` | `0x696a` |
| `0x2a1b` | `0x100924854` | `0x696a` |
| `0x571e` | `0x100924854` | `0xc161` |
| `0xbc27` | `0x10058c6e8` | `0xc161` |
| `0x5727` | `0x1005f1484` | `0xc161` |
| `0x2a7d` | `0x1005015e8` | `0xf65` |
| `0x8e61` | `0x1006ad0a8` | `0xb0c4` |
| `0x8eff` | `0x1008a2610` | `0xb0c4` |

Each retained format-12 word independently matches its target and IA diversity with address diversity 0. The 36 selected authenticated transfers also match the next retained PC and source modifier. These are logical source-pointer checks; native hardware authentication is unmeasured. [CO1, CO4-CO6; CO-A1,CO-A4]

## Verification and assumption register

Independent replay covers nine complete selected blocks in each of four retained clear classes: 36 slices, 876 original instruction visits, 112 reads, 52 writes and 36 logical authenticated edges. It compares 29,184 GP/SP values, 29,184 Q values and 912 NZCV frames. Four retained terminal views verify eight saved cells each, including the raw token. The selected slices stop before the final validation-bridge table load; that load is covered by the separate source equation and original fixup checks. No earlier admission or complete initializer interval is rerun. [CO2, CO4-CO6]

Eighteen nonvacuous UNSAT obligations cover generic token bytes, phase constants, every modeled load address, saved-field values, cursor arithmetic, base/flag partitions and raw result selection. No instruction rewrite or expression cut is used. Audit complexity is O(parent receipt bytes + selected visits*32 + source-expression DAG) time and space, excluding solver search; each query has a 30 s timeout. These are audit bounds, not native execution measurements. The checks, audit and manifest use zstd archives with decoded round-trip checks. Original inputs remain preserved. Existing reference bytes and retained traces suffice; IDA is not accessed. [CO1-CO6]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CO-A1: Exact pinned image and original fixups apply | Source instructions, constants and dispatch mapping | Check source SHA-256, every selected opcode, original pointer words and format-12 decoding. |
| CO-A2: Stated register phases and inherited conditional clear admissions apply | Block contracts and four retained views | Replay full selected GP/SP/Q/NZCV state and byte events; do not infer an alternative or native execution from clear traces. |
| CO-A3: Valid separated frame, U, token and destination memory | Load/store address and field effects | Change a saved pointer or overlap a modeled object; reject composition unless byte ordering/definedness are re-established. Keep SP+0x260 undefined. |
| CO-A4: Sequential memory epoch and logical authentication apply | Pointer reloads, saved returns and cursor cancellation | Follow exact stored pointer fields and modifiers; require continuous native custody before joining epochs. Concurrent mutation and native PAC remain unknown. |
| CO-A5: Generic source equations do not imply runtime admission | All-u32 flags/status and alternative compatibility | Enumerate low-three-bit controls; reject the inference from matching scalar equations to a native execution witness. |
| CO-A6: Raw tags and local statuses do not identify wire formats or external success | `vers` candidate, operation name and daemon-kext conclusions | Require callee/caller semantic closure, native lifetime and actual matching transport bytes/transaction IDs. |

| Impact | Bounded next evidence | Present limitation / falsification target |
| --- | --- | --- |
| High | Reduce the `0x1005015e8` nested operation for both mask4 values | Clear validation is documented separately; the alternative contract has no execution witness or native root/cache epoch. |
| High | Follow the exact-status equality target `0x1008a2610` through parent/context publication | This increment resolves the branch contract; J+0x68 and native ownership continuity remain unknown. |
| High | Pair the resulting U/parent bytes with actual daemon Mach/IOKit buffers | No new port name, right transfer, emission site or daemon-kext transaction identity is established here. |
| Medium | Establish semantic use of the `vers` tag and four-byte token | Raw provenance and byte order are exact; a conventional operation name or public schema is unknown. |
| Medium | Audit saved-cursor/continuation lifetime across nested operations | Local +32/-32 equations require a matching memory epoch for composition. |

**QG1**: factual source/ABI analysis. **QG2**: CO-A1-CO-A6 enumerate assumptions and falsification probes. **QG3**: this child-prelude/result increment is covered; the full interface goal remains active. **QG4**: explicit widths, byte units, modular arithmetic, counts and complexity. **QG5**: separate raw/interpreted bytes, status interfaces, clear traces, alternative contracts and native unknowns. **QG6**: delivery requires fresh source/replay/proof/publication verification against pinned primary artifacts. **QG7**: impact-labeled adjacent evidence and unresolved interfaces are explicit.

The [child-payload follow-up](daemon_child_payload_report.md) joins the private raw bytes 98 99 98 99 to the four packed scalar payload fields 0/1/0/1 at buffer offsets 41/45/49/53. Thirty-two fresh custody links across eight retained successful classes establish the byte decoder, encoded-scalar spill, actual producer read and destination-position read. The nested operation also requires a base compatible with mask4: set selects non-NULL U+0, clear requires non-NULL U+8. Thirteen universal obligations and 1,096 independently replayed instructions qualify this increment. The alternative execution, native caller/root/cache epochs, J+0x68 publication and daemon-kext transaction identity remain unknown. No new port emission is established; the full goal remains active.

The [subsequent child-loop report](daemon_child_loop_report.md) joins the nested result save at 0x100751f2c to its restore at 0x1006d143c, distinguishes coordinate output from raw status and follows the standard return through 0x100924854 and 0x1008c25f4 to the outer gate. Eight retained successful classes reach 0x1008a2610 with raw W27=0x8b3dc651. The private cursor is decremented by 32 B; parent J+0x68 publication and native daemon-kext pairing remain unknown.
