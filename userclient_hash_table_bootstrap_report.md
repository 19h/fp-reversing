# UserClient teardown: shared FPHashTable bootstrap and fallback

The marker-unequal arm of `_kratpzs81h` consults a module-global holder at `0xfffffe000ccceac0`. A nonnull value enters table processing. A null value requests a typed 16 B `site.FPHashTable`, then calls an initializer through an encoded private record. Only initializer output32 `0x7cb541a6` selects publication of the allocated pointer into the global holder. A nonmatching output requests typed free of that allocation. Both rollback and null allocation then reload the holder: nonzero enters processing; zero rejoins UIDList node free and the saved-successor loop. Thus this teardown path can create shared state, and its allocation-failure path retains a route to discard the current per-client node. These are conditional source contracts. [HT1-HT8; HT-A1-HT-A7]

The initializer's selected prefix decodes the caller's record, obtains the allocated object, and writes u32 values 0 at object+0 and 128 at object+4. Its remaining array construction and field preservation are covered by the linked follow-up under explicit caller, allocation and address premises. The global table's entry semantics, full marker-unequal processing, task-reference lifetime and native daemon-kext pairing remain unknown. [HT4-HT6; HT-A3-HT-A7]

Primary evidence: [original source, tables and descriptors](triage_evidence/userclient_hash_table_bootstrap_checks.json.zst), [independent audit and source queries](triage_evidence/userclient_hash_table_bootstrap_audit.json.zst), [extractor](triage_evidence/recover_userclient_hash_table_bootstrap.py), [auditor](triage_evidence/audit_userclient_hash_table_bootstrap.py), [publication verifier](triage_evidence/verify_userclient_hash_table_bootstrap_publication.py). Predecessors: [UIDList fast cleanup](userclient_uidlist_cleanup_report.md), [context lifecycle](userclient_context_lifecycle_report.md), [context/task descriptor flow](context_descriptor_task_flow_report.md), [connection close](iokit_connection_lifecycle_report.md). The available original files and captures suffice; this increment performs no new IDA access, IDB mutation, target execution or native API call.

```text
marker-unequal node -> read global holder
  nonzero -> PROCESSING
  zero -> request 16 B FPHashTable allocation
    null -> RELOAD
    nonnull -> initializer(record)
      output == 0x7cb541a6 -> publish -> PROCESSING
      other output -> typed rollback free -> RELOAD

RELOAD: read global holder again
  nonzero -> PROCESSING (frontier: 0xfffffe000a626dc8)
  zero -> UIDList node free -> saved successor loop
```

The published-success route enters processing directly; it does not take the failure reload. Every processing arrow stops at `0xfffffe000a626dc8`. Current and reloaded holder values are independent inputs to the source model; the diagram does not establish a native concurrent execution. [HT2,HT6-HT8; HT-A2-HT-A5]

## Original-byte and proof coverage

| Evidence | Scope |
| --- | --- |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original collection SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Selected source | 15 spans, 312 instructions (1248 B): 79 prior UIDList instructions and 233 newly selected instructions, including 21 initializer-prefix instructions |
| Terminal transfers | 12 instructions (48 B), including allocation, initialization, rollback and UIDList-free calls plus branches |
| Initializer capture | Complete compiler-bounded function `0xfffffe000a627400..0xfffffe000a62784c`, 275 instructions; normalized bytes equal original collection bytes |
| Original static data | Ten 256 B arrays; eight bank rules and 2048 exhaustive input cases; ten pool fixups; eleven branch fixups; two FPHashTable descriptor sites plus retained UIDList descriptor |
| New semantic audit | 12 nonvacuous UNSAT queries; 1648 modeled instruction instances across composed obligations |
| Predecessor audit | Five UNSAT queries re-solved: UIDList call/continuation and typed context free/cell clear/status return |
| Evidence rejection | Four alterations rejected: new instruction byte, new array byte, FPHashTable descriptor size and unsupported native-holder claim |
| Checks decoded SHA-256 | `440ddc3b13a08d0db1dd5b8cdedd101a53a53301f805c3686053361a94870b96` |
| Audit decoded SHA-256 | `11190d134c384308880db8f909ad86bae04ed88f0be7f1d473ca6c904ca78621` |

The original 878-instruction destroy body is verified through the reused extractor and pinned complete capture. Complete capture of either function does not imply complete interpretation. Of the initializer's 275 instructions, only the 21-instruction record/header prefix is newly modeled; 254 remain outside this prefix proof. Predecessor queries are re-solved from frozen receipts rather than freshly reconstructed in this increment. [HT1-HT8; HT-A1,HT-A7]

## Exact interface and control-flow mapping

| Evidence | Original location | Established interface |
| --- | --- | --- |
| HT1 | `0xfffffe000a626a38` -> `0xfffffe000a626a3c` | Prior marker-unequal dispatch; node+4 remains in W23, node pointer in X20 and saved successor at SP+0x60 |
| HT2 | `0xfffffe000a626aa0`; `0xfffffe000a626aa4`; `0xfffffe000a626ac0` | Resolve pool pointer to holder+4, pre-index by -4 to holder, read global u64, select allocate/processing |
| HT3 | `0xfffffe000a626b4c`; `0xfffffe000a626b68`; `0xfffffe000a626b74` | `_IOMallocTypeImpl` call: X0=FPHashTable descriptor; X10=allocation adapter; IA modifier 0xd0c8 |
| HT4 | `0xfffffe000a626c00`; `0xfffffe000a626c04`; `0xfffffe000a626c68` | Encode private request at R=SP+0x90; R+4 carries keyed token, R+8 carries allocated pointer; call initializer with X0=R, X8=initializer, IA 0x2bbe |
| HT5 | `0xfffffe000a627548`; `0xfffffe000a62754c`; `0xfffffe000a627554`; `0xfffffe000a62755c` | Decode token to W24=0xabd, load object from R+8, store header u32(0)/u32(128) |
| HT6 | `0xfffffe000a626c6c`; `0xfffffe000a626c78`; `0xfffffe000a626dac` | Consume output32 at R+0, compare to 0x7cb541a6, and publish allocated X21 through the global cell only on the matching branch |
| HT7 | `0xfffffe000a626d34`; `0xfffffe000a626d44`; `0xfffffe000a626d50` | Nonmatching-output rollback: typed FPHashTable descriptor in X0, allocated pointer in X1, `_IOFreeTypeImpl`, then transfer to holder reload |
| HT8 | `0xfffffe000a626d64`; `0xfffffe000a626d80`; `0xfffffe000a626d98` | Reload global u64; zero selects UIDList free, nonzero selects processing; restore controller pointers and dispatch phase |

The initializer uses a caller-provided record output at R+0; the cleanup tests that memory word. This is distinct from an integer return in W0. The model makes X0-X18 arbitrary at ordinary-return cuts, then supplies only the declared allocation return or initializer output seam. No native allocator failure, initializer status or ownership outcome is asserted. [HT3-HT8; HT-A3,HT-A4]

| Dispatch condition | Index / original slot | Target / IA diversity |
| --- | --- | --- |
| Initial holder null | 0x8c8 / `0xfffffe0008477560` | `0xfffffe000a626af4` / 0x0678 |
| Initial holder nonzero; published success; reloaded holder nonzero | 0x370 / `0xfffffe0008474aa0` | `0xfffffe000a626dc8` / 0x0678 |
| Allocation return null; rollback return | 0x397 / `0xfffffe0008474bd8` | `0xfffffe000a626d54` / 0x4b85 |
| Allocation return nonnull | 0x3a6 / `0xfffffe0008474c50` | `0xfffffe000a626ba4` / 0x4b85 |
| Initializer output matches 0x7cb541a6 | 0x7b9 / `0xfffffe0008476ce8` | `0xfffffe000a626d9c` / 0x9766 |
| Initializer output differs | 0x7d3 / `0xfffffe0008476db8` | `0xfffffe000a626ca8` / 0x9766 |
| Reloaded holder null | 0x39b / `0xfffffe0008474bf8` | `0xfffffe000a626920` / 0x0678 |

| Bank purpose | Original pointer slot | Resolved target after bias |
| --- | --- | --- |
| holder | `0xfffffe0008472c60` | `0xfffffe000ccceac0` |
| allocate | `0xfffffe000847a7b8` | `0xfffffe000c4ba154` |
| allocate_descriptor | `0xfffffe0008472088` | `0xfffffe000847b960` |
| initialize | `0xfffffe000847aad8` | `0xfffffe000a627400` |
| rollback_free | `0xfffffe000847a878` | `0xfffffe000c4ba368` |
| rollback_descriptor | `0xfffffe0008472178` | `0xfffffe000847b9a0` |

Original chained records retain target, raw word and authentication diversity. Their modifiers agree with the selected source transfers; successful hardware authentication remains a premise. Bank selection is checked for every unsigned byte index, and controller reads at different source PCs use independent arbitrary u32 values. Consequently, a frozen controller value across allocator/initializer calls is not required for the target-resolution proofs. [HT2-HT8; HT-A1,HT-A3]

## Shared holder, typed object and record seam

| Object / channel | Location / width | Evidence and limit |
| --- | --- | --- |
| Per-client context head | Context+0, u64 | Prior UIDList head; independent of the module-global table holder |
| Current list node | X20; node+4 marker32, node+8 successor64 | Preserved through bootstrap under the saved-frame/ABI premises |
| Shared table holder | `0xfffffe000ccceac0`, u64 | Same literal module cell consulted by this helper; runtime value and epoch unknown |
| Alloc descriptor | `0xfffffe000847b960`, 64 B normalized record | `site.FPHashTable`, signature text `21`, flags32=0x64, size32=16 |
| Rollback descriptor | `0xfffffe000847b9a0`, 64 B normalized record | Separate original descriptor site; normalized 64 B equals allocation descriptor |
| Initializer input R+4 | u32 keyed token | Original producer/consumer codec recovers raw 0xabd for this caller |
| Initializer input R+8 | u64 allocated pointer | Source store/load join; no task or Mach-name conversion |
| Initializer output R+0 | u32 | Caller compares raw word with 0x7cb541a6; unknown until supplied by callee |
| Header prefix object+0/+4 | Two u32 stores | Writes 0/128 at this source point; later preservation and full table invariants remain open |

The original collection contains eight zero bytes at the global holder address. The normalized kext reader reports that address as unbacked; it is not used to manufacture a normalized runtime value. The audit therefore gives the initial and reloaded holder separate symbolic values. Original file zeros do not prove either native read is zero. [HT2,HT8; HT-A1,HT-A2]

The caller and initializer implement different-looking record-key arithmetic. The audit first proves their u32 pre-multiply keys equal, then applies that equality by congruence through the common multiplication by `0xded29631` and XOR decoder. The subsequent header query records this certified rewrite explicitly. The decoded token is an internal control value; application semantics are unknown. The record join uses arbitrary valid frame addresses, not one fixed stack example. [HT4,HT5; HT-A2-HT-A4]

## Publication, rollback and continuation boundaries

```text
if global_holder != 0:
    goto table_processing_frontier
p = typed_allocation_request(FPHashTable_descriptor)
if p != 0:
    initializer_request(private_record(token, p))
    if record.output32 == 0x7cb541a6:
        global_holder = p
        goto table_processing_frontier
    typed_free_request(FPHashTable_rollback_descriptor, p)
if reload(global_holder) != 0:
    goto table_processing_frontier
goto UIDList_node_free_and_saved_successor_continuation
```

This is a conditional source abstraction of HT1-HT8, not the full initializer or table-processing implementation. The failure fallback is newly proved with an unequal marker; it does not reuse the earlier equal-marker premise as if it covered that case. The fallback restores W24=0x980, the full controller literal in X26 and W28's multiplier before entering the existing node-free source. Fresh composition verifies the UIDList descriptor, current-node argument, free adapter/modifier, saved successor and next/context-free target. The prior typed context free, original cell clear and raw zero-return queries are rechecked for the zero-successor join. [HT7,HT8; HT-A2-HT-A5]

The selected successful-publication path stores the allocated pointer without another holder load. No synchronization or cross-connection epoch is established by these slices. The initial/reloaded nonnull paths are not assumed to reference the same object. Every nonnull route stops before interpreting table entries at `0xfffffe000a626dc8`. [HT2,HT6,HT8; HT-A2,HT-A5,HT-A7]

For one selected node the source path uses O(1) local state and O(1) selected instructions, excluding allocator/initializer costs. Its typed request is 16 B for the table header; rollback requests free of that same pointer with an equivalent type descriptor. Native allocation footprint, backing-array size and actual retirement are unknown here. Whole-list completion requires a finite stable chain, ordinary returns and suitable branch conditions at every iteration; a later nonnull holder can enter the unrecovered processing arm. [HT3-HT8; HT-A3-HT-A5]

The outgoing calls in these slices request typed allocation, initializer work, typed rollback free or UIDList free. They add shared-state ownership context to the [Mach-port inventory](mach_ports_report.md), with no newly recovered Mach-port emission/import site. Initializer pointer, shared table pointer, context task and user connection name remain distinct. [HT1-HT8; HT-A6,HT-A7]

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| HT-A1: Pinned collection, normalized code and predecessor receipts describe this build. | All address/type/control claims | Fresh extraction compares source and pointer words, normalized/original descriptors and dependency hashes. Four altered-evidence controls must be rejected. Holder bytes are read from the collection only. |
| HT-A2: Selected node, allocated header, caller/callee frames and saved roots are valid disjoint regions; original selected tables remain available. | Record codec, header stores and fallback joins | Nonwrapping/disjoint-region premises cover both frames and protected source ranges. Recover actual allocators, node producers and frame lifetimes; an overlap or invalid root excludes composition. |
| HT-A3: Calls return ordinarily under the expected ABI, preserve saved roots/frame cells, and transfers authenticate. | Allocation/initialization/rollback continuations | Return cuts make X0-X18 arbitrary. Source restores controller pointers and full phase literals. Trace actual callee writes and original authentication modifiers; nonreturn, trap or saved-state violation falsifies the join. |
| HT-A4: Allocation pointer and initializer output are explicit abstract call outputs; input record survives until the selected decoder. | Branch classification and record/header prefix | Check every pointer/status bit pattern under path guards. Recover the initializer's remaining array path and actual allocator semantics before asserting that null or nonmatching status is natively reachable. |
| HT-A5: Global values, list state and connection/frame epochs are not silently equated. | Shared-state relation and fallback scope | Model initial/reloaded holder independently, and recover serialization, global writers and processing consumers. Whole-list completion needs the predecessor's finite/acyclic/stable-chain premises at every step. |
| HT-A6: Type strings, internal tokens and static requests do not assign application or Mach identities. | Naming and IPC interpretation | Recover node+0 producers/consumers, table-entry schema and actual port namespaces before assigning UID/task/port semantics. |
| HT-A7: Full capture and local proofs do not establish complete table initialization, processing, ownership balance or native pairing. | All continuation and completeness claims | Continue after initializer `0xfffffe000a627560` and processing frontier `0xfffffe000a626dc8`; require original-byte models and successful matching native evidence for broader claims. |

## Bounded continuation

| Impact | Next original evidence | Question resolved |
| --- | --- | --- |
| High | Remaining initializer after `0xfffffe000a627560`, including calls at `0xfffffe000a627670` and `0xfffffe000a6276fc` | Backing-array request, element stride/defaults, complete status production and post-prefix field preservation |
| High | Table-processing frontier `0xfffffe000a626dc8` and lower record consumers | What the unequal node marker selects and which shared resources are actually updated/released |
| High | Global-holder writers and head/node allocation/producer census | Source-local shared/per-client ownership, node identity and lifecycle relationships |
| High | Task-reference acquisition/release and framework stop dispatch | Whether the task-bearing context remains valid through processing and cleanup |
| Medium | Serialization and connection/build correspondence | Which source joins survive native lifecycle events and whether fairplayd uses this object/epoch |

## Scoped quality gates

- **QG1**: Claims concern source, ABI, data/control flow, object widths and evidence limits; no normative conclusion is required.
- **QG2**: HT-A1-HT-A7 specify assumptions, dependent results and falsification probes; abstract outputs and global epochs remain explicit.
- **QG3**: The global guard, typed allocation, encoded initializer request/header prefix, exact output gate, publication, rollback, reload and unequal-marker UIDList fallback are covered. Full initializer/processing and the interaction goal remain active.
- **QG4**: `312*4=1248 B`; `12*4=48 B` terminal transfers; ten arrays contain 2560 B; eight rules cover 2048 inputs. Header requests are 16 B, context requests 24 B. Extraction costs O(B+I+256R) time/space; audit construction costs O(I+256R+query DAG), plus separate SMT search with 30 s/query limits.
- **QG5**: Header prefix versus published object state, internal token versus output status, equal-marker fast path versus unequal-marker fallback, file zeros versus runtime holder, and source requests versus native outcomes remain distinct.
- **QG6**: Original bytes/fixups/type strings and exact allocator/free symbols, twelve reconstructed queries including the explicit codec rewrite certificate, five predecessor rechecks and finite-bank/rejection controls provide scoped provenance.
- **QG7**: Ranked continuation covers array construction, shared resource processing, producers, references, serialization and native correspondence without treating this bootstrap as a complete transaction or teardown.


## Shared table: backing array and initializer completion

The [initializer report](userclient_hash_table_initializer_report.md) closes the recovered token0xabd constructor path: an encoded count128/size-helper protocol supplies 3072 B to `_IOMallocTypeVarImpl`, followed by 128 entries at a 24 B stride. Raw defaults, 512 B of untouched entry padding, null/success output words and canary/return conditions are source-established. Twenty-one new obligations and three predecessor rechecks pass. Other token domains, table processing, native allocation/lifetimes and daemon-kext pairing remain unknown.


## Shared-table lookup follow-up

The [lookup contract](userclient_hash_table_lookup_report.md) joins both cleanup records to the same token0x541 helper, classifies raw empty/tombstone/occupied states, recovers the masked-key/linear-probe policy and distinguishes candidate success from an occupied-key hit. It establishes the status/flag/index channels and conditional entry+16 read; update/removal, payload ownership, native serialization and daemon-kext pairing remain unknown. No new Mach-port emission site is established.


## Shared-table reclamation and payload-free follow-up

The [reclamation contract](userclient_hash_table_reclamation_report.md) joins cleanup to the token0xc28 entry writer and token0x559 backward scan, establishes exact counter/state/key/payload transitions, and recovers the status/nonzero-payload gate for a 120 B `site.FPSecureTunnel` typed-free request. Native allocation identity, ownership, serialization and daemon-kext pairing remain unknown. No new Mach-port emission site is established.
