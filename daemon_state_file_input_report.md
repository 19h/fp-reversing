# SIDB file input, timestamp publication and first-word codec

The SIDB adapter requests a single read into the returned allocation, compares the full 64-bit read return with the metadata size, and frees the buffer on inequality. Equality publishes the private buffer pointer, requests a per-object write lock, and demands two further metadata words. Those words match current-SDK modification-time seconds/nanoseconds and are copied to the SIDB object's+8/+16 fields. After unlock and close requests, the retained continuation stops before reading the first undefined buffer byte. A separate original-source symbolic proof reduces the first four-byte construction to `BE32(buffer[0:4]) XOR 0x6703cce9`. No file content, native filesystem effect, native allocation/retirement or daemon-kext transaction is observed. [SI1-SI6; SI-A1-SI-A8]

```text
pending malloc(metadata_size)
  + declared pointer return; errno becomes unknown
  +-- NULL -> close(saved_descriptor) -> status74c29d85
  |                                    -> pending common malloc(64)
  +-- non-NULL -> read(saved_descriptor, buffer, metadata_size)
                 + declared full 64 return; buffer/errno become unknown
                 +-- return != metadata_size -> free(buffer)
                 |                              -> close(saved_descriptor)
                 |                              -> status74c29dd3
                 |                              -> pending common malloc(64)
                 +-- return == metadata_size -> private buffer pointer store
                                                -> once -> wrlock(SIDB_lock)
                                                -> unknown stat+48 word[8]
                                                   + supplied seconds
                                                -> object+8 = seconds
                                                -> unknown stat+56 word[8]
                                                   + supplied nanoseconds
                                                -> object+16 = nanoseconds
                                                -> once -> unlock(SIDB_lock)
                                                -> close(saved_descriptor)
                                                -> status8b3dc651
                                                -> first unknown buffer byte

separate symbolic lookahead; no concrete file bytes supplied:
  four bytes -> big-endian32 word -> XOR6703cce9 -> W19
```

All 256 inherited metadata contexts continue with the opposite new ABI clobber pattern. Both patterns occur across the matrix; each inherited state is not crossed again with both patterns. Six sizes receive NULL controls. Non-NULL controls have logical extents0,1 and 4096 B and stop at read requests; only the 4096 B path receives read returns and full cleanup/publication continuations. This declared coverage avoids assigning enormous owners to the other size-word controls. [SI2-SI4; SI-A2-SI-A4]

| Evidence | Primary artifact and scope |
| --- | --- |
| SI1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; original bytes, logical fixups and states retained by the [extractor](triage_evidence/recover_daemon_state_file_input.py). |
| SI2 | [Metadata report](daemon_state_file_metadata_report.md) and [parent checks](triage_evidence/daemon_state_file_metadata_checks.json.zst):256 exact contexts with six pending metadata-sized allocation states each. |
| SI3 | [Current checks](triage_evidence/daemon_state_file_input_checks.json.zst):9728 intervals, allocation/read/lifetime premises, timestamp demands, source states and first-byte cuts. |
| SI4 | [Independent auditor](triage_evidence/audit_daemon_state_file_input.py) and [audit](triage_evidence/daemon_state_file_input_audit.json.zst): independent instruction replay, owner/mask joins and twelve nonvacuous source equations, including a separately retained first-word source region. |
| SI5 | [Compile-only ABI probe](triage_evidence/daemon_state_file_input_abi.c); portable command, current SDK-relative header hashes and assembly retained in SI3. Historical native equivalence remains unknown. |
| SI6 | [Publication verifier](triage_evidence/verify_daemon_state_file_input_publication.py): exact coverage, fresh contracts/equations/SDK evidence, ten isolated original-instruction word controls in Unicorn, decoded-path scrub and publication preservation/delta checks. |

## Allocation result and exact read interface

The pending allocator is`0x100ce1d3c`, IA`0x6aa4`, SP=`0x680005fe50`. Source`0x100ce1d48` compares the full returned pointer against zero; its all-pointer equation selects index`0x7af0` for NULL and`0x7b1a` for non-NULL under the recorded phase. NULL reaches close at`0x100ac8b2c`, IA`0xee56`, with saved descriptor7. The retained complete NULL cleanup uses size4096 B and close returns0/`0xffffffff`; both produce raw status`0x74c29d85` in the three failure records below. The other five NULL size controls stop at close. [SI1-SI4; SI-A2-SI-A4,SI-A7]

Every non-NULL control returns A=`0x6600030000`, disjoint from existing model owners, without defining any byte. The zero-length owner describes zero accessible bytes; it does not assert an allocator's native usable-size or uniqueness policy. The 1 B and 4096 B controls declare precisely those accessible logical extents. No source instruction initializes the buffer before the pending read. [SI1-SI4; SI-A3,SI-A4,SI-A8]

| Source site | Interface / IA | Relevant source argument or result |
| --- | --- | --- |
| 0x100d69f9c | Size load | X2=[SP+0xc8], full 64 metadata size bits |
| 0x100d69fb0 | Descriptor reload | W0=[SP+0x5c], zero-extended into X0 |
| 0x100d69fb4 | Buffer forwarding | X1=X22=A |
| 0x100d69fc0 | read /0xee56 | X0=7, X1=A, X2=0/1/4096 for the three retained non-NULL controls |
| 0x100d69fc8 | Result comparison | Full64 X0 compared with the saved metadata word |
| 0x100cf92e8 | free /0x46a2 | X0=A after an unequal read-return control |
| 0x100ac8b2c | close /0xee56 | W0=7, recovered from the original saved descriptor |

Current-SDK `read` has signed64 `ssize_t` return, signed32 descriptor and unsigned64 `size_t` count. The read return is therefore not modeled with an int-return upper32 fixture. Both the all-u64 size-load equation and the descriptor/pointer argument equation are rebuilt from original instructions. The SDK comparison emits a size load from metadata+96 into X2 and a branch to read. This supports the ABI interpretation; no target read executes. [SI1-SI5; SI-A3-SI-A5]

## Full-width return partition and failure lifetime

Every supplied read return invalidates all 4096 payload bytes and all four errno bytes. No output payload value is supplied, including for the exact-count control. The all-u64 return/size equation selects index`0x54ae` exactly when the two64-bit words are equal and`0x5493` otherwise. For this complete continuation the requested size is4096 B. Original dispatch at`0x100d69fe8` uses IA`0x3daf`. [SI1-SI4; SI-A3,SI-A4,SI-A7]

| Supplied return64 bits | Numeric role relative to4096 | Retained next boundary |
| --- | --- | --- |
| 0xffffffffffffffff | Signed -1 control | free(A) |
| 0 | Zero count | free(A) |
| 1 | Smaller count | free(A) |
| 4095 | Smaller count | free(A) |
| 4096 | Exact count | once at0x10043e508 |
| 4097 | Synthetic count above request | free(A) |
| 0x100000000 | Synthetic high32 count control | free(A) |

The last two are register perturbations, not valid native output observations or claims of buffer writes beyond the request. The all 64-bit equation covers every return/size bit combination under its phase premises; the finite controls independently check the retained paths. No second read is requested before the unequal branch reaches free. Native retry behavior inside library code, interruption effects and file contents remain unknown. [SI1-SI4; SI-A3,SI-A4,SI-A8]

For the -1 control, a separate declared void free return retires only the 4096 B model owner. Its arbitrary GP return fixture is not a status. The next request is close(7); declared close returns0 and`0xffffffff` both reach the common pending malloc(64), producing raw status`0x74c29dd3`. No retained post-retirement source access touches the retired extent. This is a model-lifetime/source-flow result, not an observed native free or descriptor release. [SI1-SI4; SI-A3,SI-A4,SI-A8]

| Path | Adapter record+28 at0x68000600d4 | Caller record+16 at0x6800070dc8 | Outer cell0x68000659b4 |
| --- | --- | --- | --- |
| Selected NULL allocation cleanup | 0x74c29d85 | 0x74c29d85 | 0x74c29d85 |
| Selected unequal read/free cleanup | 0x74c29dd3 | 0x74c29dd3 | 0x74c29dd3 |
| Selected exact read / timestamp / close | 0x8b3dc651 | 0x8b3dc651 | Not this failure-channel store |

The original status stores are`0x100ccedd4`, `0x10043d33c` and, on the two failure routes, `0x100712c9c`. These private record fields are distinct from ordinary GP return values and from the heap pathname object's+28 field. The common failure wrapper allocation at`0x100710758`, IA`0x6aa4`, X0=64, remains pending; its payload and ownership remain unknown. [SI1-SI4; SI-A6-SI-A8]

## Exact-read pointer and timestamp publication

The exact-count path stores the full buffer pointer at private cell`0x6800062008` through`0x100be5e10`, before requesting the write lock. The all-pointer equation proves the original store independently of the concrete A address. This cell is not the heap SIDB object's+8 field. The source calls a lock adapter with a private record at`0x680005ff50`; the later unlock call reuses that record address. Complete record types remain unknown. [SI1-SI4; SI-A3,SI-A6-SI-A8]

| Original site | Source role / interface | Relevant binding |
| --- | --- | --- |
| 0x100be5f14 ->0x10043e280 | Write-lock adapter call, IA0x6aa4 | X0=0x680005ff50 |
| 0x10043e508 | pthread_once, IA0x8489 | X0=0x1010b8cd0, X1=0x10040ebd4 |
| 0x100361df4 | pthread_rwlock_wrlock, IA0x4c4d | X0=L=0x6600007000 |
| 0x100be5f18 ->0x100be5f1c | Metadata load and store | stat+48 ->SIDB_object+8, width8 B |
| 0x100be5f20 ->0x100be5f24 | Metadata load and store | stat+56 ->SIDB_object+16, width8 B |
| 0x100be5fc0 ->0x1004423f8 | Unlock adapter call, IA0x6aa4 | Same private record address |
| 0x100442650 | pthread_once, IA0x8489 | Same control/callback arguments |
| 0x100208efc | pthread_rwlock_unlock, IA0x5431 | X0=L |
| 0x100ac8b2c | close, IA0xee56 | Saved descriptor7 |

These synchronization returns use control0 for ABI pattern0 and 35 for pattern1. The values are linked controls, not a full cross-product or observations of native acquisition success. Once completion without additional callback effects is an explicit premise. The imported lock/unlock effects remove all 200 lock-byte definitions; once effects remove all 16 control-byte definitions. No original source access in this increment touches either opaque extent. [SI1-SI4; SI-A3,SI-A4,SI-A6]

After the write-lock return, execution stops before `LDR X8,[SP,#0x98]` at`0x100be5f18`. The demanded address is`0x680005fee8`=stat+48, width8 B, with all bytes unknown. Supplying only that word produces the object+8 store, then stops before `LDR X8,[SP,#0xa0]` at`0x100be5f20`, demanding`0x680005fef0`=stat+56. Only after that separately supplied word can the object+16 store execute. No stale stack bytes become timestamp values. [SI1-SI4; SI-A3-SI-A5]

Current-SDK assertions establish `offsetof(struct stat,st_mtimespec)=48 B`, `sizeof(struct timespec)=16 B`, seconds offset0/width8 and nanoseconds offset8/width8, both signed64 field types. Thus the two source demands correspond to modification-time fields under the SDK comparison. Native historical layout and actual timestamp values remain unknown. The bit-transfer equations cover every 64-bit word, independently of valid timestamp ranges. [SI1-SI5; SI-A4,SI-A5]

| Supplied seconds64 bits | Supplied nanoseconds64 bits | Role |
| --- | --- | --- |
| 0 | 0 | Zero-word control pair |
| 1 | 999999999 | Nonzero pair; SDK field units s/ns |
| 0xffffffffffffffff | 0x8000000000000000 | Synthetic signed-boundary pair; not a native timestamp observation |

The only heap pathname-object writes across all 9728 intervals are those two eight-byte stores. The SIDB object's lock pointer, byte+24, word+28=`0xffff5b81`, path and undefined gaps retain their exact prior representations. All other inherited non-errno owners and generated J+`0x34`32 B also retain their exact defined bytes and gaps. The loader's native caching policy, object+28 meaning and lifetime remain unknown. In particular, the previous object+8 zero/nonzero consumer now has a source-backed timestamp producer; its general invalidation behavior still needs a cross-phase proof. [SI1-SI4; SI-A2,SI-A7,SI-A8]

| Offset (B) | Width (B) | Source-derived role after timestamp publication |
| --- | --- | --- |
| 0 | 8 | Raw pointer to the separately modeled rwlock |
| 8 | 8 | Supplied stat+48 word; current-SDK modification-time seconds |
| 16 | 8 | Supplied stat+56 word; current-SDK modification-time nanoseconds |
| 24 | 1 | Preserved value1; full meaning unknown |
| 25 | 3 | Preserved undefined gap; no C padding type is inferred |
| 28 | 4 | Preserved0xffff5b81; full semantic type unknown |
| 32 | 34 | Preserved SIDB inline pathname, including terminal NUL |
| 66 | 8 | Preserved undefined tail |

This is a source-derived logical view of the 74 B owner, with 63 defined bytes and 11 undefined bytes, not a recovered complete C type. The timestamp stores replace previously defined zero words and do not close the gaps. Payload opacity likewise records unavailable byte values in the model; actual native writes remain unobserved. [SI1-SI5; SI-A4,SI-A5,SI-A7,SI-A8]

## First file-content demand and compact word construction

After the selected timestamp/publication route and declared close return0, raw status`0x8b3dc651` is present in the adapter/caller records. The model still carries A as an initially undefined4096 B owner. Execution reaches`0x1005b94fc`, `LDRB W10,[X28,W10,UXTW]`, with X28=A and W10=0, then stops before the one-byte read. The buffer pointer has reached a source consumer; no payload byte has been invented or inferred from the read count. Native delivery, file identity and content remain unknown. [SI1-SI4; SI-A3,SI-A4,SI-A7,SI-A8]

The independent auditor separately lifts original`0x1005b94fc..0x1005b9550` with four unconstrained byte variables and the recorded scalar phase constants. The original byte addresses are offsets0,1,2 and 3. Flattened arithmetic and Boolean operations reduce to this exact32-bit expression:

```text
W19 = ((u32(b0)<<24) | (u32(b1)<<16) | (u32(b2)<<8) | u32(b3))
       XOR 0x6703cce9
```

The negated expression is unsatisfiable over all 2^32 four-byte combinations. Each retained first-byte boundary checks the same scalar phase constants and X28 binding; the proof's original source bytes are retained separately in SI4. This is symbolic lookahead from an unknown-byte cut, not execution with a recovered SIDB header. The word's file-format meaning, validation, expected values and subsequent use remain unknown. [SI1,SI3,SI4,SI6; SI-A1,SI-A3,SI-A7,SI-A8]

The publication verifier also executes only these 21 original instructions in an isolated Unicorn instance for ten explicit four-byte controls. These fixtures are separate from the retained loader continuations and are not recovered file contents. They check the symbolic lift against a second execution method; all 210 instruction executions stop at`0x1005b9550`, without an API call or further parser instruction. [SI1,SI4,SI6; SI-A1,SI-A7,SI-A8]

| Isolated four-byte input | W19 output32 |
| --- | --- |
| 00000000 | 6703cce9 |
| ffffffff | 98fc3316 |
| 01000000 | 6603cce9 |
| 00010000 | 6702cce9 |
| 00000100 | 6703cde9 |
| 00000001 | 6703cce8 |
| 12345678 | 75379a91 |
| 89abcdef | eea80106 |
| 6703cce9 | 00000000 |
| 98fc3316 | ffffffff |

No new Mach port/right, emission site, IOKit selector, kext call or native cross-layer transaction is established by this file-to-word path. Heap pointers, timestamp words, status records and an XOR-encoded input word have distinct source roles. [SI1-SI4; SI-A6-SI-A8]

## Advertised function starts and code-site provenance

The original Mach-O's `LC_FUNCTION_STARTS` contains 1005 advertised starts. Its compressed table occupies 1864 B at file offset17603576 B, SHA-256 `ce02892286eaa20b5ad18e05d3a348a5c4b20ab49c668be14fd9e2eb119ccd54`. The publication verifier independently decodes its ULEB128 deltas relative to `__TEXT`=`0x100000000` and queries the original symbol table. None of the nine exact sites below has a symbol-table name. These descriptions are recovered source roles, not recovered symbols. [SI1,SI6; SI-A1,SI-A7,SI-A8]

| Queried entry or site | Preceding advertised start | Next advertised start |
| --- | --- | --- |
| 0x100d3d658 | 0x100d3d658 | 0x100d3e6d8 |
| 0x100d3e6d8 | 0x100d3e6d8 | 0x100d3e968 |
| 0x10043d044 | 0x10043d044 | 0x10043d36c |
| 0x10043e280 | 0x10043e280 | 0x10043e574 |
| 0x1004423f8 | 0x1004423f8 | 0x100442688 |
| 0x100ce1d3c | 0x100ccf52c | 0x100ce20c8 |
| 0x100d69fc0 | 0x100d65598 | 0x100d7c6ec |
| 0x100be5f18 | 0x100ba8510 | 0x100c9e894 |
| 0x1005b94fc | 0x100559b7c | 0x10061748c |

The direct adapter call targets match advertised starts, while several imported-call and word-construction sites sit in other advertised brackets. A start table does not establish complete code-chunk membership or shared-thunk ownership. The recovered calls and authenticated logical edges therefore supply the control-flow evidence used here; interval containment alone does not assign those sites to one contiguous routine. Full function/chunk ownership remains unknown. This metadata pass is O(image bytes + advertised starts + symbol entries) time and O(advertised starts) additional space. [SI1-SI4,SI6; SI-A1,SI-A7,SI-A8]

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| SI-A1: The pinned image, logical fixups and decoder describe the analyzed build. | All original-source claims. | Rehash the whole image, compare every retained opcode, independently replay GP/Q/NZCV/SP and byte effects, and check logical authenticated edges. Hardware PAC validity is not established. |
| SI-A2: The 256 inherited contexts describe the conditional incoming metadata phases. | Coverage, object masks and saved descriptor/size bindings. | Join every parent exactly; check pointer-partition phase constants and the opposite-pattern rule. Different call epochs, object+8 paths or parent states require new joins. |
| SI-A3: Imported returns obey the modeled ordinary arm64 ABI. | Post-import control/data flow, full 64 ssize_t results and status paths. | Check callee-saved registers/lanes, both clobber patterns across the matrix and all state joins. Counterfactual positive/large returns are not native observations. Nonreturning calls require separate evidence. |
| SI-A4: Logical owner extents, retirement and output opacity are explicit premises. | Buffer lifetime, unknown contents, scalar metadata demand and cleanup. | Require disjoint0/1/4096 B model owners with no defined bytes; invalidate payload/errno before read continuation; remove only the 4096 B owner after declared free. Reject invented content or source access after retirement. Native usable size and ownership remain unknown. |
| SI-A5: Current SDK declarations provide an ABI comparison for the historical target. | ssize_t/size_t widths, st_mtimespec offsets and timestamp units/type names. | Compile exact probes, retain SDK-relative header hashes and assembly, and compare a matching historical SDK/runtime before asserting equivalence. Numeric source offsets remain valid independently of that naming comparison. |
| SI-A6: Synchronization calls complete with only the declared modeled effects. | Timestamp publication sequence, controller state and native-effect boundaries. | Track once16 B/lock200 B opacity, original adapter stores and request arguments. Completion without additional callback effects is explicit; successful native acquisition/release and scheduling are unknown. |
| SI-A7: Reused records and parser scalar constants have their recorded phase meanings. | Status channels, timestamp fields, private pointer forwarding and first-word codec. | Check exact record destinations, heap+8/+16 stores, unchanged gaps/other owners, all parser seed registers and the rebuilt all-four-byte query. A different phase must be proved separately. |
| SI-A8: Local pointers, pending calls and symbolic word construction imply no native delivery or file-format meaning. | Lifetime/exposure conclusions and bounded follow-ups. | Obtain matching native file identity, API outcomes, allocation/content provenance and transaction/epoch joins before assigning transport, ownership, header semantics or daemon-kext pairing. Those facts remain unknown here. |

## Coverage, algorithms and receipts

A complete fresh extractor run reproduced the retained checks exactly:256 contexts,9728 intervals and 884480 source visits. The independent replay and publication verification are separate checks. The first-word algorithm is four byte loads, shifts/ORs and one XOR, O(1) time and O(1) space for one32-bit output. It is a compact source-equivalent expression under SI-A7, not a complete file parser. [SI1-SI4,SI6]

| Coverage | Exact count |
| --- | --- |
| Inherited contexts / new contexts | 256 /256 |
| NULL controls:6 per context | 1536 |
| Non-NULL controls:0/1/4096 B extents | 768 |
| Full64 read-return controls:7 per context | 1792 |
| Selected NULL close controls | 512 |
| Declared mismatch free returns / close controls | 256 /512 |
| Exact-read lock continuations | 512 |
| Independently supplied timestamp pairs | 768 |
| Source intervals / visits | 9728 /884480 |
| Source reads / writes | 217856 /44800 |
| Logical edges / original source calls | 30464 /2816 |
| Nonvacuous original-source equations | 12 |
| Separate isolated Unicorn word controls / instructions | 10 /210 |
| Original Mach-O advertised starts / queried site brackets | 1005 /9 |

Each context retains38 intervals. Therefore256 x38=9728 intervals exactly. A selected timestamp pair supplies8 B seconds+8 B nanoseconds=16 B;768 pairs supply12288 scalar bytes across alternate continuations. These are repeated validation quantities, not native traffic or allocation footprints. Each non-NULL owner starts with zero defined bytes, and no read result supplies payload values. [SI3,SI4,SI6]

| Equation | Scope |
| --- | --- |
| all_pointer_bits_original_NULL_allocation_partition | Every 64-bit pointer; NULL/non-NULL source dispatch under the recorded phase. |
| all_u64_original_read_size_argument | Every saved size word transferred to X2 without narrowing. |
| all_descriptor_and_buffer_bits_original_read_arguments | Every saved descriptor32 and buffer pointer64; exact argument/IA setup. |
| all_u64_read_return_and_size_exact_equality_dispatch | Every pair of64-bit size/return words; exact equality partition. |
| all_pointer_bits_original_unequal_read_free_argument | Every buffer pointer forwarded to free with IA0x46a2. |
| all_pointer_bits_original_exact_read_private_publication | Every output-cell pointer and buffer pointer; exact original store. |
| all_u64_original_timestamp_seconds_publication | Every seconds word stored unchanged at object+8. |
| all_u64_original_timestamp_nanoseconds_publication | Every nanoseconds word stored unchanged at object+16. |
| all_four_byte_values_original_first_word_big_endian_XOR_codec | All 2^32 input-byte combinations under retained parser scalar constants. |
| all_u32_adapter_record_status_store | Rebuilt preceding source equation for arbitrary raw status at adapter+28. |
| all_u32_caller_record_status_store | Rebuilt preceding source equation for arbitrary raw status at caller+16. |
| all_u32_close_return_independent_first_dispatch | Rebuilt preceding first-dispatch independence equation; complete current paths use declared finite controls. |

Each query checks a satisfiable unnegated setup and an unsatisfiable negated contract with 30 s solver timeout. Original-source replay checks registers, vectors, NZCV/SP, byte effects and authenticated logical edges. Time/storage are O(parent bytes + source visits x retained register/effect state + owner/state joins + query DAG + owned artifact bytes), with the stated per-query solver bound. SDK probes compile from stdin to stdout assembly; no target API executes. [SI1-SI6]

```text
python triage_evidence/recover_daemon_state_file_input.py
python triage_evidence/audit_daemon_state_file_input.py
zstd --ultra -22 -q -T1 triage_evidence/daemon_state_file_input_checks.json
zstd --ultra -22 -q -T1 triage_evidence/daemon_state_file_input_audit.json
python triage_evidence/validate_rpc502_sidecar_delivery.py
zstd --ultra -22 -q -T1 triage_evidence/interface_manifest.json
python triage_evidence/verify_daemon_state_file_input_publication.py
```

Use Python with Unicorn, Capstone and Z3 and place `triage_evidence` on its module search path. Verify archive round trips before removing duplicate plaintext files. The existing source module locates the original binary. The retained compiler command uses `<SDK>` as its portable placeholder. All new artifacts, decoded interval payloads and the actual commit message undergo the analyst-path scrub. [SI1-SI6]

The [interface manifest](triage_evidence/interface_manifest.json.zst) retains both the ten isolated word-control results and the Mach-O function-start brackets in this increment's validation records. The publication verifier recomputes and compares those records along with the source/audit counts. [SI1-SI6]

| Independent replay | Exact count |
| --- | --- |
| register_values_checked | 28614656 |
| NZCV_values_checked | 894208 |
| vector_register_values_checked | 28614656 |
| read_bytes_checked | 1376256 |
| source_visits | 884480 |
| original_authenticated_edges_checked | 22272 |
| write_bytes_checked | 295680 |

The model joins verify 8192 API returns,1536 scalar-output joins,8634368 repeated opaque-output byte checks,256 declared owner retirements,768 timestamp-pair publications and 768 first-byte demands. The ten isolated word controls and 1005 function-start/9 bracket checks are separate publication validations. Repeated byte checks are validation quantities, not native allocation or transfer footprints. [SI3,SI4,SI6]

| Logical artifact | SHA-256 |
| --- | --- |
| Current checks | `cdd60c06abc58fbb4b891ef851c6fa563ccff2fe671057d135a3633af379bd2b` |
| Independent audit | `03f9d598480d49ba7f28e9d31379c1892aae2ac366175811139ba42d5ee042bf` |
| Extractor | `8a409b21b0a876dfb15cfa2456b8fc5eff820f7556edf71daf28b1e3bfdaa0d1` |
| Auditor | `b34d172cde85dd99122b42412345183f3c1d28f23a836058baff85033acaf842` |

These are decoded-artifact hashes; archive hashes differ. The verifier checks decoded values, the exact publication delta and preservation of all three original inputs. [SI1-SI6]

## Bounded continuation opportunities

| Impact | Follow-up | Required evidence / boundary |
| --- | --- | --- |
| High | Establish the first decoded word's consumer and file-format role. | Original def-use, comparisons and subsequent bounded field demands. The XOR equation alone does not establish magic, version, length or cryptographic meaning. |
| High | Trace file-derived state into daemon/kext payload producers. | Source producer/consumer identities plus matching native transaction/epoch evidence. No Mach/IOKit delivery is inferred from the returned heap pointer. |
| Medium | Join timestamp producers to the earlier object+8 zero/nonzero consumer. | Cross-phase source/owner continuity and the actual comparison policy. A timestamp word is not a buffer pointer or proof of cache validity. |
| Medium | Establish native allocation and descriptor cleanup. | Matching historical allocator/read/free/close semantics and actual outcomes, including interruption and short-count behavior. Model retirement/request sites do not establish native release. |
| Medium | Recover the common64 B wrapper and status consumers. | Original allocation return, payload stores and downstream record interpretation; retain adapter+28/caller+16 distinction. |
| Medium | Establish metadata/file identity and synchronization outcomes. | Native lookup/opened-object identity, timestamp provenance, callback/locking behavior and call epochs; current SDK names alone are insufficient. |
| Medium | Establish shared fragment/thunk and function ownership. | Original call/branch graph and matching database chunks; LC_FUNCTION_STARTS brackets alone do not establish ownership of cross-bracket sites. |
| Low | Resolve zero-length allocator/read behavior and the other size controls. | Matching historical library semantics and further source contracts. The current zero-length control stops at read(count0); larger non-NULL extents are not supplied. |

## Quality gates

- **QG1**: Pass. Factual original-source, ABI and provenance analysis.
- **QG2**: Pass. SI-A1 through SI-A8 list premises, dependent results and falsification probes.
- **QG3**: Pass for this increment. All 256 parents, allocation controls, read/count partition, selected cleanup, timestamp publication and first input demand are covered by the stated matrix. The full interface goal remains active and incomplete.
- **QG4**: Pass. B denotes bytes; descriptor/status words are32 bits, sizes/ssize_t/timestamp words64 bits. Timestamp field units are s/ns under the SDK comparison; synthetic raw bits are identified. Counts, offsets, full-width arithmetic and complexity are explicit.
- **QG5**: Pass. Logical zero extents, signed64 return bits, unknown payload/metadata, distinct pointer/status fields, conditional lock effects and symbolic lookahead are separated. Native identities/effects and file-format semantics remain unknown.
- **QG6**: Pass. Pinned image/opcodes/fixups, independent replay, twelve rebuilt nonvacuous equations, ten separate original-instruction word controls, SDK probes/header hashes/assembly and exact publication receipts provide primary provenance.
- **QG7**: Pass. The impact-labeled continuation table bounds file-format, cross-layer data flow, lifetime, timestamp and environmental follow-ups.

The [word-routing continuation](daemon_state_word_routing_report.md) follows the first four bytes into two private stores and exact lower/upper comparisons. The middle interval reaches a pending64 B allocation; both outer ranges reach a second pathname lstat request after an explicit borrowed-errno return. Native contents and file-format meaning remain unknown.
