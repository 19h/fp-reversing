# SIDN cleanup and conditional 64-byte state-object construction

All 76 published pending SIDN-query states continue through the retained metadata/removal matrix. Twelve terminal paths per state request `free` on the same 4096 B input-buffer pointer. After a declared void return, all 912 paths preserve raw caller status `0x74c29dbe` into a private status cell and reach malloc(64). SIDN's three raw status classes propagate through two private records but are not read by the outer caller before this allocation request. This closes a local status-consumption boundary; it does not establish the final public status or a general policy of ignoring filesystem errors. [CC1-CC6; CC-A1-CC-A5,CC-A8]

Each incoming state's link-type branch additionally crosses declared NULL and fresh non-NULL allocator returns. NULL publishes an encoded zero pointer at context J+0x68 and reaches the SIDN metadata-access adapter's errno request. Non-NULL initializes 53 of 64 owner bytes, copies 24 context bytes into the object and reaches a pending 21 B allocation. The non-NULL context-slot publication, payload meaning, eventual result and native lifetime remain unknown. [CC1-CC6; CC-A2-CC-A8]

```text
all 76 inherited pending SIDN lstat states
  + zero -> fresh mode demand
  |          + link type --------------------- raw 74c29dd3 --+
  |          + selected non-link -> unlink                   |
  |                                  + nonzero -> 74c29dd3 --+
  |                                  + zero -> sync requests |
  |                                            zero fields  |
  |                                            8b3dc651 ----+
  + nonzero -> borrowed errno pointer -> demand errno32      |
                                         + 2 -> 74c29dd1 ---+
                                         +13 -> 74c29dd3 ---+
                                                           v
                           pending free(A), A owns 4096 B in model
                           + declared void return / owner retirement
                           carried status 74c29dbe -> private cell
                           pending malloc(64)
                             |
                    allocator controls on link route per parent
                       + NULL -> encoded NULL -> J+68
                       |         -> SIDN metadata adapter
                       |         -> ___error pending
                       + S -> initializer + field updates
                              -> J+1c[24] copied to S+18
                              -> 53 defined / 11 undefined B
                              -> malloc(21) pending
```

No native target API, filesystem operation, allocation/free, hardware pointer authentication, IPC or IDB mutation executes. Logical owner retirement removes the model's right to use bytes; it is not an observed allocator operation or a source wipe of 4096 B. [CC1-CC6; CC-A3-CC-A8]

| Evidence | Primary artifact and scope |
| --- | --- |
| CC1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; original instructions/fixups in the [extractor](triage_evidence/recover_daemon_state_container_construction.py). |
| CC2 | [SIDB removal/SIDN handoff report](daemon_state_path_removal_report.md) and [parent checks](triage_evidence/daemon_state_path_removal_checks.json.zst): four parent contexts with 19 pending SIDN queries each. |
| CC3 | [Current checks](triage_evidence/daemon_state_container_construction_checks.json.zst): all 76 parents, 3116 source intervals, opaque effects, retirement/fresh-owner premises and exact state journals. |
| CC4 | [Independent auditor](triage_evidence/audit_daemon_state_container_construction.py) and [audit](triage_evidence/daemon_state_container_construction_audit.json.zst): instruction replay, complete state/owner joins, status windows, field masks, pointer-copy provenance and 24 source equations. |
| CC5 | [Compile-only arm64e probe](triage_evidence/daemon_state_container_construction_abi.c): malloc/free prototypes, LP64 widths, metadata constants and stat/once/rwlock extents; source, assembly and SDK-relative header hashes retained in CC3. |
| CC6 | [Publication verifier](triage_evidence/verify_daemon_state_container_construction_publication.py): exact all-parent coverage, rebuilt equations, original-byte/fixup checks, 18 Mach-O site brackets, decoded path hygiene, preserved inputs and publication delta. |

## SIDN metadata, removal and local status use

The incoming SIDN lstat is at `0x1004cd194`, IA `0xf401`, X0=D+32=`0x6600008020`, X1=`0x680005ff18`, SP=`0x680005fef0`. Its carried pathname is `/var/db/fpsd/SC Info/SC Info.sidn`. Four declared int-return controls are 0,0xffffffff,1,0x80000000. All invalidate 144 B of stat output and four errno bytes before continuation. A zero result demands the two undefined mode bytes at SP+44=`0x680005ff1c`; nonzero results request the borrowed errno pointer at `0x1005797c4`, then stop before its undefined four-byte read. [CC1-CC6; CC-A2-CC-A4]

Mode controls 0xa000 and 0x81a4 represent the link-type and non-link partitions. Each of the three nonzero lstat controls crosses errno words 2 and 13. The selected non-link path crosses four unlink-return controls and, after unlink zero, two four-call synchronization sequences with status 0 or 35. The source phases and all-u16/u32 local predicates are rechecked from the preceding increment: lstat zero/nonzero, `(mode & 0xf000)==0xa000`, errno==2 and unlink zero/nonzero. Complete paths remain finite controls. Positive/high-bit lstat and unlink returns and synchronization status 35 are synthetic perturbations, not native observations. [CC1,CC3-CC6; CC-A1-CC-A4]

| SIDN outcome in retained matrix | Raw adapter/caller status | Subsequent request |
| --- | --- | --- |
| Nonzero lstat, supplied errno 2 | 0x74c29dd1 | free(A) |
| Nonzero lstat, supplied errno 13 | 0x74c29dd3 | free(A) |
| Supplied link-type mode | 0x74c29dd3 | free(A) |
| Nonzero unlink | 0x74c29dd3 | free(A) |
| Zero unlink and declared synchronization returns | 0x8b3dc651 | free(A) |

Both u32 status stores are preserved: `0x1004af644 -> 0x68000600d0` and `0x10041ac4c -> 0x6800070dc8`. After the latter store, the retained terminal intervals do not read that outer status cell; neither do the following free-return intervals before malloc(64). At `0x100863fac`, source instead restores X22 from X21. The pending free boundary has W22=`0x74c29dbe`, and original `0x100689e0c` later stores that carried value to `0x68000659b4`=outer SP+0x58b4. The SIDN outcome and carried status therefore have distinct local data-flow roles. Final status aggregation and interpretation remain unknown. [CC1,CC3,CC4,CC6; CC-A2,CC-A4,CC-A8]

The SIDN synchronization calls reuse the once control/callback but use SIDN lock L=D+0x1000=`0x6600009000`, rather than the earlier SIDB lock. Pending sites are once `0x10043e508`/IA0x8489, wrlock `0x100361df4`/IA0x4c4d, once `0x100442650`/IA0x8489 and unlock `0x100208efc`/IA0x5431. Their SP is `0x680005fe80`. Once returns invalidate 16 B and assume no additional callback effects; lock/unlock returns invalidate all 200 L bytes. The source does not access those opaque bytes. `0x100628a28` writes two u64 zeros to D+8 and D+16, already zero in the inherited states. Native acquisition, callback scheduling and allocation retirement are not established by those stores. [CC1,CC3-CC6; CC-A2-CC-A4,CC-A8]

## Buffer retirement and common allocation boundary

| Original site | Interface / IA | Argument or effect in retained model |
| --- | --- | --- |
| 0x10074aa04 | Source pointer reload | Eight bytes at outer SP+0x1f08=0x6800062008 yield A=0x6600030000 |
| 0x10074aa20 | free / 0x46a2 | X0=A; pending before each declared void return |
| 0x100689e0c | Private status store | u32 0x74c29dbe at 0x68000659b4 |
| 0x1007106f0 -> 0x100436378 | Leaf call / 0x58a3 | Writes raw 0x8b3dc650 at private caller record 0x6800070db8 |
| 0x100710758 | malloc / 0x6aa4 | X0=64 B; all 912 cleanup continuations converge here |

The declared free return retires the existing A/4096 B owner and invalidates its complete byte view plus errno. It supplies an arbitrary void-return GP value and the opposite new ABI pattern while preserving the callee-saved state. Every subsequent retained interval has no A owner or defined A bytes, and no current interval reads or writes any A byte. The prior four prefix bytes are therefore not reinterpreted as construction input. No source wipe or native deallocation is inferred. [CC1,CC3-CC6; CC-A2-CC-A5]

The 64 B allocation is the same call site previously reached from open/fstat failure paths. This increment establishes concrete source convergence for the new SIDN-cleanup states, without assuming that all historical callers supply equivalent private state. The constructor's ten-file inventory does not itself imply a ten-file cleanup loop: these selected states reach buffer free after SIDN. The other eight pathname objects' later access order remains unknown. [CC1-CC4,CC6; CC-A2,CC-A8]

## Allocator return, pointer representation and exact field mask

For each of the 76 incoming states, the link-type cleanup path receives two allocator controls: NULL and a fresh, disjoint S=`0x6600040000` owner of 64 B with no initial definitions. The other 836 terminal allocation requests remain pending. The source adds bias K=`0x4aba552460e435c6` at `0x10071076c` and stores `pointer+K` modulo 2^64 in outer SP+0x26e0=`0x68000627e0`. The initializer's inverse `0xb545aadb9f1bca3a` cancels K modulo 2^64. This is an additive pointer representation; it is distinct from authenticated control-flow fixups. [CC1,CC3-CC6; CC-A1,CC-A5,CC-A6]

| Source condition | Established representation and continuation |
| --- | --- |
| Allocator NULL | Encoded pointer is K. `0x100901498` stores K to J+0x68=0x6500115b88; the nonzero stored word decodes to NULL. |
| Allocator non-NULL | Private encoded pointer is S+K. Call `0x1006c23b0 -> 0x100413164`, IA0x6240, initializes the fresh owner; no J+0x68 store occurs before the pending 21 B allocation. |

The NULL branch calls `0x1006965b0 -> 0x10042f208`, IA0x6aa4, then `0x10042f4b8 -> 0x100618fdc`, IA0xe200, then `0x100619234 -> 0x1006176f8`, IA0x11d8. It stops at imported `___error` request `0x10063c2f8`, IA0x6e96, SP=`0x680005feb0`, carrying SIDN object D in X20. The following metadata query and its output are not newly continued. This is a source-selected fallback into the metadata-access adapter; it is not proof of a native retry or successful file access. [CC1,CC3,CC4,CC6; CC-A2-CC-A6,CC-A8]

The non-NULL initializer uses scalar stores and a zero vector store. A source u64 write at S+0x14 overlaps adjacent logical fields; later writes replace it. The final retained mask must therefore be derived from ordered byte writes, not from an assumed packed C structure. [CC1,CC3,CC4,CC6; CC-A2,CC-A6,CC-A7]

| Final S offset | Extent | Defined value at pending malloc(21) |
| --- | --- | --- |
| 0x00 | u64 / 8 B | 0 |
| 0x08 | u64 / 8 B | 0x8b3cc6508b3ac658 |
| 0x10 | u64 / 8 B | 0xda660f258b3dc650 |
| 0x18 | 24 B | Exact bytes copied from J+0x1c; first u32 is 6, remaining 20 B are zero in these parents |
| 0x30 | 8 B | Undefined |
| 0x38 | u32 / 4 B | 0x21b97d7f |
| 0x3c | u8 / 1 B | 0 |
| 0x3d | 3 B | Undefined |

Defined bytes total `8+8+8+24+4+1=53`; undefined bytes total `8+3=11`; `53+11=64 B`. Exact mask holes are offsets 48..55 and 61..63 inclusive. Unknown bytes are not implicit zero padding. Field types and meanings beyond the observed widths/representations remain unknown. [CC1,CC3,CC4,CC6; CC-A2,CC-A6,CC-A7]

Source call `0x100595f84 -> 0x10046f89c`, IA0x34a1, has X0=J+0x1c=`0x6500115b3c`, X1=S+0x18 and W2=24. The retained alignment selects byte-copy instructions; all 24 source loads and consecutive destination byte stores are independently replayed. The argument order is source, destination, count on this helper. A general memcpy/memmove identity, arbitrary overlap behavior, all alignments or arbitrary-length safety is not claimed. The all-pointer source equation establishes this call's argument construction; full copy behavior is checked on the retained 24 B cases. [CC1,CC3,CC4,CC6; CC-A1,CC-A6,CC-A7]

The next pending allocation is `0x1009342fc`, IA0x6aa4, X0=21 B, SP=`0x6800060100`. Its payload and purpose remain unknown. The original generated 32 B at J+0x34 remain unchanged across all 3116 intervals. The copied context field precedes that stream and does not derive from the retired input-buffer bytes. A format-version interpretation of the copied word 6 requires producer/consumer evidence beyond its numerical equality to earlier range components. [CC1,CC3-CC6; CC-A2,CC-A6-CC-A8]

## Authenticated pointer-copy provenance and arithmetic replay

The independent replay joins original authenticated loads through their private saves and reloads before matching each branch's original slot word and IA modifier. It verifies the original value, save address, reload address, event order and absence of intervening overwrites, then verifies every register and byte event in the source chain. These are direct source-produced pointer copies within the current intervals, not matches to an unexplained inherited pointer value. No hardware PAC execution is claimed. [CC1,CC3,CC4,CC6; CC-A1,CC-A2]

| Branch site / target | Original slot / IA | Source load -> save -> reload | Private save relative to outer SP |
| --- | --- | --- | --- |
| 0x1006902ec -> 0x1008b394c | 0x101040278 / 0x3ecb | 0x1006c3e6c -> 0x1006c3e70 -> 0x1006902e4 | +0x3aa8 |
| 0x1006b7728 -> 0x1006991ac | 0x101044d98 / 0x3275 | 0x10087768c -> 0x100877690 -> 0x1006b7710 | +0x4e20 |
| 0x100831198 -> 0x100595ec0 | 0x10103e1c8 / 0x44f6 | 0x100665680 -> 0x100665684 -> 0x100670198 | +0x9110 |
| 0x100939c84 -> 0x10070a2e4 | 0x101045180 / 0x0e73 | 0x10084a76c -> 0x10084a774 -> 0x100947068 | +0x9c18 |

Four ADC instructions in the non-NULL path are modeled as `u32(left+right+C)` with flags preserved, at 0x100946fd4,0x100946ff0,0x100947024,0x100947058. Four independent source equations cover every u32 operand and carry value; concrete replay checks all 304 occurrences against the following GP/NZCV frames. This extends the replay vocabulary for actual source instructions without treating skipped arithmetic as an opaque effect. [CC1,CC3,CC4,CC6; CC-A1,CC-A2]

Eighteen sites are bracketed by the original 1005-entry LC_FUNCTION_STARTS table, SHA-256 `ce02892286eaa20b5ad18e05d3a348a5c4b20ab49c668be14fd9e2eb119ccd54`, 1864 B at file offset 17603576. Initializer 0x100413164 and copy-helper 0x10046f89c are advertised starts; the other inspected fragments are not. No exact-site original symbol is present. Complete noncontiguous chunks, original semantic names, all callers and public interfaces remain unknown. The original image and retained files were sufficient for these claims; IDA was not queried for this increment. [CC1,CC3,CC4,CC6; CC-A1,CC-A2,CC-A8]

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CC-A1: Pinned original image and logical fixups apply | Source sites, equations, branches and candidate routine roles | Check image SHA, every opcode, slot word/target/modifier, direct load/save/reload chains and original function-start brackets; do not substitute native PAC claims. |
| CC-A2: All 76 published SIDN states are conditional entries | Complete retained cleanup paths, masks and status windows | Exact GP/Q/NZCV/SP/owner/known-byte joins for each parent/query key; preserve prior synthetic prefix and native-epoch limits. |
| CC-A3: Current arm64e SDK supplies modeled ABI widths/extents | int/pointer/size_t/void terminology; 144/16/200 B opaque spans | Recompile type/layout assertions and malloc/free assembly; verify SDK-relative header hashes; historical runtime equivalence unknown. |
| CC-A4: Declared API returns, scalar controls and opaque synchronization effects apply | Metadata/removal routing and SIDN zero stores | Invalidate complete spans, demand unknown bytes before insertion, cross int/errno/mode/status controls, verify source phase seeds and rebuild local all-bit equations; no additional once callback effects assumed. |
| CC-A5: Declared free return retires the A/4096 B model owner | Subsequent known-byte exclusion and no-dereference claims | Remove owner and all byte definitions, invalidate errno, check full ABI/memory join and every later read/write; logical retirement is not an observed wipe/free. |
| CC-A6: Link-route allocator controls are NULL or a disjoint fresh 64 B owner | Two allocator branches per parent, 53/11 B mask and pending malloc(21) | Prove exact pointer encoding, compare ordered writes and undefined holes, preserve unknown initial bytes; other 836 terminal allocations remain pending. |
| CC-A7: Carried J header and retained copy geometry apply | 24 B source-to-object copy and current first word 6 | Verify source/destination/count, byte read/write order, actual data, masks and no J+0x68 write on non-NULL path; arbitrary data/alignment/overlap/length semantics and field meanings remain unknown. |
| CC-A8: Source stores and pending requests do not establish native effects or final exposure | Ownership, aggregate status, file effects, complete function role and IPC limits | Require downstream consumers, runtime identity and transaction/epoch correlation before claiming native retirement, public status or daemon-kext transport. |

## Reproduction, coverage and bounded continuation

Checks logical SHA-256: `1d19f7bc139ef5a334eb536ffc6f47a6f176553211402458b2a82fb649260ade`. Audit logical SHA-256: `1db414094dfe83752510cf330f25090c8f2b1fc63a75d1911c1a9481e47c4ea6`. Receipt JSON and the manifest use `zstd --ultra -22 -q -T1`. Raw, structured and decoded hexadecimal payloads are checked for analyst-local paths. Target-defined state-file paths remain technical evidence. [CC3-CC6]

Per parent, `4 stat + 2 mode + 3 errno-accessor + 6 errno-word + 4 unlink + 8 synchronization-return + 12 free-return + 2 allocator-return = 41 intervals`; `76*41=3116`. All 76 published parents are covered. The full 1543-parent earlier SIDB frontier is not retroactively expanded. The journals retain 486552 source visits, 109972 reads, 26296 writes, 17860 logical edges and 1520 internal calls. The current API/owner contracts check 1444 ordinary returns, 608 scalar joins, 912 retirement joins and 152 allocator joins; 1824 SIDN raw-status stores, 912 carried-status stores, 152 lock-pointer pairs and 304 direct authenticated pointer-copy chains are checked. [CC2-CC4,CC6]

Independent replay checks 15669376 scalar and 15669376 vector register values, 489668 flag states, 715616 read B, 150556 write B and 13756 original authenticated edges. Construction checks repeat 4028 defined B, 836 undefined B and 1824 copied B across 76 alternative objects. These repeated counts describe conditional coverage, not distinct native allocations/events or native memory usage. [CC3,CC4,CC6]

Twenty-four nonvacuous source equations comprise ten retained local metadata/status/path equations plus fourteen allocator-encoding, initializer/field-store, context/private-store, free/copy-argument and ADC equations. Solver limit is 30 s/query. Arithmetic is exact u16/u32/u64 with modulo wrap; lengths/offsets are bytes. Extraction is O(parent bytes+retained visits+effects+SDK source) time/storage; replay is O(V*(register state+effects)+owner joins+query DAG) time and O(receipts+largest interval+known byte map) storage. No native timing or memory cost is measured. [CC1-CC6]

| Impact | Next evidence | Architectural purpose and present boundary |
| --- | --- | --- |
| High | Non-NULL pending 21 B allocation and later S/context consumers | Recover payload purpose, actual object publication and eventual status/data transport; current non-NULL J+0x68 publication is not established. |
| High | NULL-path errno return and SIDN metadata/read continuation | Establish the next concrete query instance and its descriptor/output contract; current request stops before the errno accessor. |
| High | Downstream carried-status and aggregate-result consumers | Distinguish local non-use of SIDN status from final error handling and public API results. |
| High | Compare the [middle-word-range malloc(64)](daemon_state_word_routing_report.md) with this constructor path | Shared size and raw record word 0x8b3dc650 do not establish shared payload, caller policy or object identity. |
| High | Native file/allocator/IPC epoch correlation | Pair source cleanup/construction with actual daemon-kext/deeper events; none is established here. |
| Medium | Other 836 terminal allocator states and nonzero object fields | Broaden full-path coverage and test whether header/context differences affect construction. |
| Medium | Context-header producer, unknown object bytes and copy-helper generality | Establish field types and format meaning; word 6 and exact 24 B copy do not establish a complete format or generic library identity. |

**QG1** passes: factual source/ABI analysis. **QG2** passes: CC-A1-CC-A8 document dependencies and falsification probes. **QG3** passes for this all-parent SIDN cleanup/conditional-construction increment; the full interface goal remains active. **QG4** passes: exact widths, masks, extents, counts and complexity. **QG5** passes: local status non-use versus final status, logical retirement versus native free, encoded NULL versus zero bytes, private storage versus context publication and finite copy geometry versus generic semantics remain distinct. **QG6** passes after independent replay, 24 rebuilt equations, current compile/source/fixup checks, preserved-input checks and exact publication verification. **QG7** passes: bounded expansion covers allocator consumers, fallback metadata access, aggregate status, native correlation, remaining states and header/layout semantics.
