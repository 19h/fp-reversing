# Mode471C object removal, destruction and heap ABI

Source/ABI-model analysis establishes mode471C as a keyed object-removal and destruction path. After the previously recovered tag/key lookup, it finds an object by raw-u32 header equality, unlinks either the head or an interior node, requests free of optional buffers at object+0x310 and+0xD8, overwrites872 bytes, requests free of the object, clears the selected16-byte key record, and decrements a u32 counter. Matching cases write encoded-zero result `0x8B3DC651`; exhausted chains write raw `0x74C29F00`. Native allocation/publication, object type, complete callers and cross-layer transport linkage remain unknown [OC1-OC14].

The recovered overwrite is compact and independent of prior object bytes. For aligned SP and selected mode471C:

```text
S = u64((SP+0x2BA0)+0x2F40B33D2E85D192)
for i in 0..871:
    b = u8(S+i)
    object[871-i] = u8(((u8(b+0x6E) XOR0xBA) * u8(b+0x7F)))
```

The stored byte repeats after256 counter increments. Its source seed depends on a stack address; no entropy or cryptographic-strength claim is made. The hardcoded destruction extent matches one inspected872-byte allocator candidate, but a continuous allocator-to-registry path is not established. The full daemon/kext/deeper-interface investigation remains active.

Evidence: [18 original call-boundary paths](triage_evidence/daemon_object_consumers_profiles.json), [24 extended paths](triage_evidence/daemon_object_consumers_continuations.json), [three occupied-counter paths](triage_evidence/daemon_object_consumers_counters.json), [source/contracts](triage_evidence/daemon_object_consumers_contracts.json), [17 proof pairs](triage_evidence/daemon_object_consumers_proofs.json), [96 independent A64 replays](triage_evidence/daemon_object_consumers_replays.json), [12 counter A64 replays](triage_evidence/daemon_object_consumers_counter_replays.json), [independent checks and512 original-block cases](triage_evidence/daemon_object_consumers_checks.json), [guard IDB bytes](triage_evidence/daemon_object_consumers_live_ida.json), [cleanup/unlink IDB bytes](triage_evidence/daemon_object_consumers_more_ida.json), [allocation-candidate IDB bytes](triage_evidence/daemon_object_consumers_alloc_ida.json), [preservation](triage_evidence/daemon_object_consumers_preservation.json), and [scoped gates](triage_evidence/daemon_object_consumers_quality_gates.json). The [preceding registry report](daemon_registry_lookup_report.md) retains the earlier boundaries.

## Assumption register

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| OC1 | Addresses identify thin arm64e SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. | Rehash source,compare18 spans,138 original fixups,every retired opcode and1,312 fresh IDB raw bytes. |
| OC2 | Original caller39C894 and its declared frame/bank/controller premises apply. Native incoming reachability is unknown. | Retain continuous original prefixes with no fixture PC transitions; match all18 earlier call-boundary prefixes exactly. |
| OC3 | Registry bounds,bases,key records,headers and links are initial environment inputs. | Exercise head/interior/exhausted chains and NULL/non-NULL fields under three placements/controller sets. Native publishers remain unknown. |
| OC4 | Private objects have4096-byte owners; field tokens have eight-byte owners. These extents are fixtures. | Check every observed owner-relative read/write and retirement. Native allocation size/provenance and field contents remain unknown. |
| OC5 | The characterized chains are finite and point to declared nodes. | Compare head replacement,predecessor replacement and exhausted traversal; source-local proofs cover arbitrary link/header values. Cyclic or invalid native graphs are not validated. |
| OC6 | Imported free calls return through a void ABI model with arbitrary X0/volatile GPR/SIMD/NZCV and preserved callee state. | Verify exact targets,slots,modifiers,arguments and source restoration; independently replay four physical backings. No native free executes. |
| OC7 | Once is initially completed and synchronization uses the established models. Actual native lock ownership is unknown. | Check acquisition before mutation and cleanup afterward; retain primitive status0/22 cases. Native concurrency and pointer stability remain unknown. |
| OC8 | Source phase471C,SP alignment16 and recorded bank roots apply to the overwrite composition. | Prove the aligned-SP seed and literal constants; vary stack low-byte placement and exhaust all256 counter bytes at two remaining lengths. |
| OC9 | Unspecified bytes remain arbitrary until source-written; owner retirement rejects later accesses. | Retain symbolic identities and check full source effects/A64 backings. The overwrite body has no object-data read. |
| OC10 | Main fixtures inherit zero at counter1010C5754; supplemental fixtures explicitly start at3. | Prove decrement for every u32 counter and verify0->FFFFFFFF separately from3->2; exhausted supplemental traversal leaves3 unchanged. Native counter production is unknown. |
| OC11 | Field-token sharing and unselected-node references are input features; native graph validity is not established. | Observe only the selected node's free requests and retained reads/writes. The completed model does not validate later users of unselected references. |
| OC12 | The872-byte allocation candidate has the stated incoming bank-root premise. | Exhaust its256-byte bank,verify malloc slot and literal argument. Native phase and continuous registry publication remain unknown. |
| OC13 | IDB raw bytes and displayed decoding have different coverage. | Check ten raw ranges and preserve five partial macro rows/eight undecoded byte rows separately. No IDB mutation occurs. |
| OC14 | PAC and original library calls are logical abstractions. Raw result interpretation follows the established XOR convention. | Check authenticated slots/modifiers/return tokens,SP restoration and raw stores. Native PAC/library behavior and original error names remain unknown. |

## Removal and ownership sequence

```text
outer tag32 -> selected key64/header32 -> payload32 record
  |
  +-- payload+10 -> current object
  |      compare object.u32[0] with selected raw header/token
  |      mismatch: previous=current; current=current.u64[360]
  |
  +-- match at head: payload.u64[10] = current.u64[360]
  +-- match inside chain: previous.u64[360] = current.u64[360]
  |
  +-- current+310 non-NULL -> free(buffer310)
  +-- current+D8 non-NULL -> free(bufferD8)
  +-- overwrite current[0..367], descending,872 byte stores
  +-- free(current)
  +-- clear selected key record / active_counter -=1
  +-- request unlock / write encoded zero / free eight-byte query input
  +-- stop before unknown caller-frame dereference39C998
```

Offsets10/360/310/D8/367 in the diagram are hexadecimal. The27 completed compositions contain13 head removals and10 interior removals; four chains are exhausted. The latter request no object/buffer free or key clear. Every path restores the original caller SP and reaches the same pre-dereference boundary at `0x10039C998` [OC2-OC7].

| Source PC | Established operation | Access/argument |
|---|---|---|
| `0x100A264E0` | Replace payload head | `MEM64[payload+0x10] = MEM64[current+0x360]` |
| `0x100926C0C` | Replace predecessor link | `MEM64[previous+0x360] = MEM64[current+0x360]` |
| `0x100BDF330` | Request free of+0x310 value | X0 is the full64 field value |
| `0x100BE0E80` | Request free of+0xD8 value | X0 is the full64 field value |
| `0x100A1BF7C` | Write next overwrite byte | Descending address,one byte/iteration |
| `0x100BD9D88` | Request object free | X0 reloaded from saved object at SP+0x2F18 |
| `0x100B11D94` | Decrement counter1010C5754 | u32 modular subtraction |
| `0x10095F074` | Publish result | u32 at original record+16 |
| `0x10039C988` | Request query-input free | Original eight-byte owner |

Both unlink identities are proved for arbitrary u64 link values. The interior path preserves the payload head and updates the predecessor. The source retains the matched object locally for destruction. Field semantics beyond their free arguments remain unknown; the requests establish heap-ABI touch points without identifying the native buffer formats.

## Exact imported ABI and source restoration

All four free call sites resolve through original slot `0x10109FF30`, import `_free` from libSystem, IA modifier `0x46A2`. The three new source bank rules independently collapse for all256 byte inputs:

| Call | Left/right bank roots | Key | Additive | Constant/index |
|---|---|---|---|---|
| free+0x310 | 0x100FC4230 /0x101031FA0 | 6C | CB81 | 87 /CC08 |
| free+0xD8 | 0x100E99A00 /0x100F4E390 | D7 | CB7C | 8C /CC08 |
| free object |0x101031DA0 /0x100E99900 | 86 | CBB0 | 58 /CC08 |

The remaining numeric columns are hexadecimal. The established SDK signature is `void free(void *)`; no return status is inferred from X0. SourceBDF328 saves the current object in callee-saved X19 before the+0x310 free, then BDF334 restores X4 from X19. The object-free path preserves its dispatch phase in X21 before calling free and resumes through the original source table. Arbitrary volatile state in the models does not prevent the retained compositions from completing [OC6,OC14].

Across27 completed compositions, the source requests54 once calls,27 write locks,27 unlocks and70 frees:10 buffer310,10 bufferD8,23 objects and27 query inputs. Native implementations are opaque. The source journals request these operations; the checker does not invoke their host counterparts.

## Compact overwrite contract

The seed construction at BB1574..BB15CC reduces under SP&15=0 to:

`S = u64((SP+0x2BA0)+0x2F40B33D2E85D192)`.

The source constructs the overwrite length by adding `0xC8FA055AF58A065C` to `0x3705FAA50A75FD0C`, yielding `0x368` modulo2^64. The loop decrements its remaining length, stores one byte at `object+remaining-1`, increments the counter, and repeats while remaining is nonzero. Full-width source proofs establish these operations. With a valid872-byte span, it performs exactly872 stores from+0x367 through+0, in O(872) time and O(1) loop state [OC8-OC9].

| Quantity | Established value |
|---|---|
| Stored byte | `u8(((u8(S+i+0x6E) XOR0xBA) * u8(S+i+0x7F)))` |
| Counter period of stored byte |256 |
| Original object byte consumed by loop | None |
| Observed destruction span |872 bytes,0x368 |
| Declared private object owner |4096 bytes; source free carries no extent argument |
| Native allocation size and erasure guarantee | Unknown |

The27 cases verify20,056 overwritten bytes across23 matched objects. The two original placements differ by256 and therefore produce the same low counter byte; six added cases use a16-byte placement change. The observed starting bytes are92 andA2. The checker also executes the original26-instruction write block for all256 low counter bytes at remaining lengths1 and872:512 cases/13,312 source visits. Its write effects are exactly the saved remaining-length word and one object byte. Whole-path A64 replay checks the original loop edges and all subsequent free/cleanup effects.

## Key metadata, counter and returned results

For the selected key slot at outer index I, source clears u64+0 to `0xE3B88695C0D52DBC` and u32+8/+0x0C to `0x8B3DC651`, matching the earlier initializer constants. It then performs `u32(C-1)` at `0x1010C5754`. The new proof covers every u32 C under the retained index bound I<3. This counter is separate from the outer capacity/bound at1010C67D0 and inner bound at1010CA2B0 [OC3,OC10].

The main fixtures inherited file-image zero at the counter, so21 removals produce FFFFFFFF. That is conditional fixture arithmetic. Two supplemental occupied-key removals explicitly start at3 and produce2; the supplemental exhausted chain retains3. No native underflow or defect is established. The source publisher for the native counter remains unknown.

| Outcome | Cases | Raw result | XOR8B3DC651 interpretation |
|---|---|---|---|
| Matched object removed/destroyed |23 |8B3DC651 |0 |
| Chain exhausted |4 |74C29F00 |Signed32 -42671 |

The existing source applies these results before releasing the eight-byte query input. The following caller-frame value at SP+0x5B0 is still unknown; the checker stops before its use as a read address. An original symbolic error name and subsequent transport interpretation remain unknown.

## Allocation anchor and architectural boundary

A bounded census of literal `MOV W0/X0,#872` finds one original-text site: `0x100C116A8`, followed by a call at `0x100C116B0`. Under incoming X14=100F4E390 and the captured savedSP+2998 root100E99A00, its byte bank selects malloc at slot10109FF58, IA modifier6AA4. The returned pointer is saved at SP+0x2C08 before its NULL gate. This candidate has the same size as the destruction span. Its complete allocation-to-registry publication path and native incoming phase remain unknown [OC12].

No new daemon Mach send/receive, right disposition, message ID or IOKit emission is established in these cleanup paths. The original daemon imports retired here are synchronization/free interfaces; library internals and native allocator/kernel activity are outside the model. The [annotated RAX packet audit](triage_evidence/zut_trap_argument_audit.json) remains separate transport evidence. No new trace packet is correlated with mode471C.

## Verification and bounded continuation

| Check | Coverage |
|---|---|
| Original boundary-stage inputs |18 paths;exact source-prefix agreement with the corresponding extended paths |
| Extended inputs |24 cleanup variants plus3 occupied-counter variants;740,553 continuation visits |
| Independent A64 |108 compositions;3,010,164 source visits;all recorded effects and final boundaries checked |
| Fresh checker replay |Two additional complete compositions |
| Isolated original write block |512 cases,13,312 source visits |
| Source identities |17 pairs,34 persisted UNSAT queries,17 rebuilt obligations,143 lifted instructions,four satisfiable premise witnesses |
| Original provenance |18 spans,138 fixups,four exhaustive bank rules (1,024 inputs),six dispatch slots |
| Live IDB |Ten raw ranges,1,312 bytes,304 displayed rows,five partial macro rows,eight undecoded byte rows |
| Unique continuation opcodes |2,340 retired and one additional inspected/unretired boundary opcode |

```sh
export PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages
export Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_object_consumers.py
```

Artifact/journal construction is linear in retained bytes/events/expression construction apart from solver work; each query has a30 s limit. Under valid finite chains and owners, the characterized scan/removal work is O(N+M+L+872), where L is the traversed node count; loop state is O(1). Native faults, cycles and imported-body behavior are outside that bound.

| Impact | Next bounded investigation | Discriminating evidence |
|---|---|---|
| High | Follow candidate allocationC116B0 through initialization and publication. | Source-order stores can establish the actual object allocation and counter/registry lifecycle. |
| High | Recover native callers producing the eight-byte removal query. | Record-to-Mach/IOKit provenance can connect this local mode to an external interface. |
| High | Resolve caller SP+5B0's incoming definition. | A source-derived owner/target can continue beyond39C998 without an arbitrary pointer fixture. |
| Medium | Recover buffer310/D8 allocation sites,contents and ownership relationships. | Establish payload formats and native lifetime beyond the observed free arguments. |
| Medium | Establish native counter producers and synchronization discipline. | Replace explicit registry-state premises with continuous native-source provenance. |

## Scoped quality gates

QG1 passes for factual technical analysis. QG2 is covered by OC1-OC14 and probes. QG3 passes for this object-destruction increment; the full objective remains incomplete. QG4 covers u8/u32/u64 arithmetic,byte spans,modular counter behavior and algorithm/solver bounds. QG5 separates source requests from native effects,private owner size from destruction extent,zero-counter fixtures from occupied-counter inputs,and candidate allocation from proven publication. QG6 covers original source/fixups,independent A64,source proofs,exhaustive byte cases and fresh IDB bytes with decoding limits explicit. QG7 is covered by the impact-bounded continuation table.
