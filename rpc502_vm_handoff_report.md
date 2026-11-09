# RPC502 reply-copy factory to consuming copyout/discard

Original send-side code now supplies its produced VM-copy objects and backing bytes directly to original copyout/discard components through exact whole-memory snapshots. This replaces the independent copy-object fixture at the receiving component boundary for the selected type-3 cases. The components use original-file policy G=2/V=0 with explicitly supplied source-map/thread prerequisites. Successful consuming copyout and later discard, allocation/copy failure followed by discard, NULL copies, source-removal ordering and map-context restoration are checked. Native transport, VM effects, allocator retirement and a complete daemon/kext transaction remain unknown.

Primary evidence: [original functions and roles](triage_evidence/rpc502_vm_handoff_source.json), [18 CPU cases and compressed exact memory snapshots](triage_evidence/rpc502_vm_handoff_profiles.json), [independent replay and ownership-channel oracles](triage_evidence/rpc502_vm_handoff_checks.json). Inputs reuse exact [normalized reply seed frames](triage_evidence/rpc502_reply_copyin_profiles.json), descended from the previously recovered [original daemon/MIG reply](triage_evidence/rpc502_reply_bridge_profiles.json). Extent substitutions remain declared private fixtures; real application outputs are not established. No target, VM, IPC, native free, hardware PAC, IDB or saved-memory mutation occurs. [VH1-VH3]

## Previously separate interfaces now joined

```text
original normalized RPC502 reply seed (reply ID 602)
  -> original outgoing OOL converter + VM-copy factory
       source-map removal request -> copy publication -> descriptor store
       produces copy0/backing0 and copy1/backing1
  -> exact complete private RAM + image-global transfer
       +-> original consuming copyout(copy0)
       |     success -> mapped output; copy0 release/zeroing protocol
       |     -> original discard(copy1)
       |
       +-> original copyout(copy0), declared allocation/copy error
             preserves copy0; mapped output zero
             -> original discard(copy0) -> original discard(copy1)
```

Every arrow between CPU components is explicit orchestration, using a separate fresh CPU and the exact preceding memory state. It does not stand for an executed native queue, transport or kext continuation. Error alternatives clone the same successful producer state into independent epochs. Aggregate release counts across those branches are not one native reference ledger. [VH2,VH7]

The complete original kernel collection hash is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Source recapture contains 23 complete functions / 4492 instructions and 32 exact instruction-role checks. Captured lower allocator/release bodies are not thereby executed. The ordinary FairPlay kext caller sites remain the [previously established copyout/discard paths](kext_port_vm_report.md):

| Kext site | Established role | This increment's evidence boundary |
|---|---|---|
| `0xfffffe000a60d61c` | Copy OOL0 into `kernel_map` using exported copyout | Executes the bound kernel wrapper/consumer on actual factory-produced state; this kext call site is not resumed |
| `0xfffffe000a6123cc` | Discard non-NULL OOL1 on the inspected normal path | Executes original discard on produced copy1 under an explicit component transition |
| `0xfffffe000a611790` | Discard OOL0 after copyout error, then optionally OOL1 | Separate error components preserve copy0; subsequent discard calls use the exact preserved state |

These identify why the two-copy protocol concerns the FairPlay reply. They do not generalize its ownership result to every RPC700 reply or alternative sentinel path. [VH1-VH2,VH8]

## Original function and emission/consumption sites

| Address | Exact identity / inferred role | Retained behavior |
|---|---|---|
| `0xfffffe000bcc42f0` | Anonymous outgoing message-body conversion | Original normalized descriptor traversal and conversion |
| `0xfffffe000bdd15a4` | Anonymous VM-copy input implementation | Original selected type-3 construction |
| `0xfffffe000bdd1ffc` | Source-region removal call | Requested before object publication; lower VM effects modeled |
| `0xfffffe000bdd1f38` | Copy-object output publication | Original pointer store |
| `0xfffffe000bcc4a30`-`...4a44` | Descriptor pointer signing/store | Original logical data-sign path, discriminator `0x5d4f` |
| `0xfffffe000bdd1574` | Exact `_vm_map_copyout` | Original object-extent load and consuming call |
| `0xfffffe000bdcb374` | Anonymous internal mapper | Original type dispatch and extent contract |
| `0xfffffe000bdcbbb0` | Anonymous type-3 copyout helper | Allocation/copy, context, consumption/error protocol |
| `0xfffffe000bdc6308` | Exact `_vm_map_copy_discard` | Original payload clearing and release/zeroing requests |
| `0xfffffe000bdcc234` / `...bdcc374` | Anonymous map-context enter/restore | Original X8 result record and restoration; lower switch is modeled |

Exact nlist identities, raw original bytes and inferred roles are kept distinct. Kernel descriptor pointers remain VM-copy identities, not daemon-local names or mapped byte addresses. No new Mach endpoint is established. [VH1]

## Environmental and source-map prerequisites

The factory starts with original-file u32 policy cell `0xfffffe0007e6a01c`=2 and u32 V at `0xfffffe0007f8b5f0`=0. Native runtime values remain unobserved. The source map supplies page shift14, declared range bounds, NULL+0x58 and clear u32+0xb0 bit25. Thread owner word+0x420 is zero. These prerequisites select the tested type-3 route for the positive extents; the earlier source used an explicit G=0 fixture. This is a refreshed conditional G=2 result, not a claim that every G=2 runtime takes that route. See [policy predicate](kernel_copyin_policy_report.md). [VH3-VH4]

Original VM-copy input calls carry `(source_map, source_VA, extent, options=1, out_copy)`. Option bit0 comes from the daemon reply's deallocate byte; no optional bit9 is set in these clear-source-map-bit fixtures. The original factory requests source removal before publishing each positive copy. A later copy discard does not request restoration of that source mapping. Actual source removal and daemon cleanup after native send errors remain unproved. [VH3,VH5]

The declared source map and destination `kernel_map` are different objects. Thread current map initially equals the source map. The type-3 copyout's original other-map branch increments the destination map reference, enters a context, copies, restores context and returns the reference to its initial value3 where reached. The lower switch model writes only the private thread current-map field. Native address-space switching, scheduling and translation are not executed. [VH4-VH6]

## Produced objects and exact transfers

| Producer reply extents, bytes | Original produced copies | Receiving component result |
|---|---:|---|
| (0, 0) | 0 | Exported NULL copyout writes address0; NULL discard has no release |
| (1, 37) | 2 | OOL0 maps exactly 1 produced byte; OOL1 is separately discarded |
| (4096, 8192) | 2 | OOL0 maps exactly 4096 produced bytes; OOL1 is separately discarded |
| (32768, 1) | 2 | OOL0 maps exactly 32768 produced bytes; OOL1 is separately discarded |

Original type-3 headers publish backing pointer at+0, zero at+0x10, u64 extent at+0x20 and type byte3 at+0x2d. Positive headers and backing payloads come from the original factory, with allocation and byte-copy leaf effects declared. NULL descriptors leave the unused private header-storage sentinels untouched; those sentinel bytes are not allocated live copies. [VH3-VH5]

Each component transfers the complete 1048576-byte private RAM image and all declared image-global cells. Compressed zlib/base64 records retain the exact byte length and SHA-256; the fresh replayer decompresses independently and compares every final byte. Fourteen transfers therefore cover `14 * 1048576 = 14680064 bytes`. Eighteen fresh final-state checks cover `18 * 1048576 = 18874368 bytes`. Compression is storage only; it changes no source or private-memory semantics. CPU entry arguments are explicitly rebuilt for each separate component, rather than presented as native CPU/queue continuity. [VH7]

The original outgoing message retains its descriptor pointer bits after a consuming copyout or discard component. The pointed-to wrapper has undergone the recorded zeroing/release protocol. Those stale descriptor bits do not establish another owned object. This is the same representation/lifetime distinction previously identified for the kext scratch field. [VH5-VH7]

## Outcome, release and context channels

Two error branches use the (1,37) producer. Each starts from its exact original successful factory state.

| Copyout outcome | Returned u32 / address | Wrapper0 protocol | Next supplied component |
|---|---|---|---|
| Success | 0 / declared mapped address | Original payload clear; payload-release request; declared header zeroing; header-release request | Discard produced copy1 |
| Allocation leaf returns6 | 6 / 0 | Produced wrapper/backing preserved | Discard copy0, then copy1 |
| Byte-copy leaf returns5 | 1 / 0 | Produced wrapper/backing preserved; original destination cleanup requested | Discard copy0, then copy1 |
| NULL copy | 0 / 0 | No wrapper or release | NULL discard |

Discard has a void contract here; its recorded X0/u32 bits are not a status interpretation. The three successful mappings carry exactly `1 + 4096 + 32768 = 36865` produced bytes. Four original X8 context save/restore pairs cover those three successes and the byte-copy error; allocation error does not enter that context path. Each 24-byte record contains the previous map, NULL associated pointer and two zero u32 words. The thread map and destination reference count are checked from final memory after every component. [VH5-VH7]

For page shift14 and these aligned mapped outputs, allocation extent is `R = 16384 * ceil(N/16384)` bytes. The N=1 copy-error cleanup requests `[mapped, mapped+16384)` in the destination map. Its removal flags differ from the send-side source-removal request. The original error-statistics cell `0xfffffe000cb810f0` changes from the declared epoch7 to8 in that error branch and is carried unchanged through its subsequent discards. It remains7 in the other branches. This private counter is not a native failure observation. [VH4-VH7]

Ten payload-clear/payload-release/header-release sequences are checked across independent branch epochs: three consuming successes and seven non-NULL discards. Actual allocator retirement, native mapping contents after a failed partial copy and complete ownership balance remain unknown. The failed-copy model writes no bytes. [VH5-VH8]

## Assumption register and falsification probes

| ID | Assumption / dependent results | Stress test or falsification probe |
|---|---|---|
| VH1 | Hash-pinned collection and earlier kext bindings describe the intended static artifacts | Recapture all 23 functions / 32 roles; verify runtime kernel/kext pairing and slides separately |
| VH2 | Exact normalized reply seed represents the supplied header/namespace prefix | Compare prior original MIG/normalizer provenance; join authentic header/namespace/transport state before a complete exchange claim |
| VH3 | File G=2/V=0 plus declared source-map/thread fields select the tested factory route | Check original values and executed branches; attest runtime policy, actual source flags, owner and reply extents together |
| VH4 | Page shift14, private map bounds/zone geometry and stable map/thread fields are valid premises | Check exact metadata and restored fields; native initialization, concurrency and map lifetime require separate evidence |
| VH5 | Allocation, copy, lock, removal, header-zeroing and release leaf models have the declared results | Rebuild effect bytes from arguments; recover native lower contracts and partial-copy effects before native ownership claims |
| VH6 | Original context helpers may be joined under a private pending-work record with clear flags | Check all 24 saved bytes, map switch arguments and final references; cover real pending work and associated objects separately |
| VH7 | Complete RAM/global snapshot equality establishes these separate component handoffs | Compare all 1048576 bytes, source effects and globals per transition; recover actual queue/caller/task continuity before native timing claims |
| VH8 | Only type-3/NULL copy representations and the stated ordinary FairPlay reply sites are covered | Complete type-2 and policy-forced alternatives, protected caller paths and actual RPC/daemon state before generalization |

## Verification and bounded continuation

Eighteen independent CPU replays check 3321 original instruction visits, 630 writes / 4706 bytes, 787 reads / 5502 bytes, 89 API models and 31 independently rebuilt effect patches / 82536 bytes. All 18 final boundaries, complete RAM images and 126 declared global records match. Six original type-3 objects, six ordered source-removal/publication/descriptor joins, 14 complete state transfers, three produced-payload copyouts and ten release sequences are verified. Logical PAC steps remain explicit; no authentication success is asserted.

Reproduce from the extracted directory:

```text
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_rpc502_vm_handoff.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_rpc502_vm_handoff.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_vm_handoff.py
```

Recovery is O(image + captured source bytes) time/space. Collection/replay are O(visits + total RAM bytes + effect bytes) time and O(image + journals + one private RAM image) working space; retained case snapshots contribute their compressed artifact sizes. Validator range membership tests at most 23 captured functions per source visit. All byte/page arithmetic above is exact in the tested non-wrapping domain, with no measurement uncertainty. Finite branch cases do not estimate native frequencies.

| Impact | Bounded continuation | Evidence it would add |
|---|---|---|
| High | Actual header/namespace -> queue -> daemon/kext continuation | Replace the component transitions with authentic caller/receiver identity and transport |
| High | Type-2 and policy-forced copy construction/consumption | Cover representations not established by the current G=2/map prerequisites |
| High | Mapped-region installation, page use, close/unwire lifetime | Connect wrapper retirement to the separate mapped-byte lifetime |
| Medium | Lower allocation/free and real map-switch effects | Replace retirement, geometry and context models |
| Medium | Native policy and actual reply extents | Determine which conditional factory path a real FairPlay exchange uses |

QG1: Factual technical analysis; no normative judgment is required.
QG2: VH1-VH8 enumerate assumptions, dependencies and falsification probes.
QG3: Scoped factory/consumer roles, descriptor publication, map/task context, source/destination cleanup, NULL/error branches and respective reports are covered; the broad goal remains active.
QG4: u32/u64 fields, bytes/pages, exact full-memory extents, release versus status channels, algorithm costs and reproduction commands are explicit.
QG5: Source versus destination removal, file/private/native policy, stale descriptors, independent branch epochs, modeled retirement and unexecuted transport are distinguished; uncovered representations remain unknown.
QG6: Original hashes/functions/symbol roles, exact normalized seeds, complete snapshot hashes and independent source/effect replay provide primary evidence; no new native or IDA observation is claimed.
QG7: Impact-labelled continuation remains bounded to unresolved FairPlay transport and VM interfaces.

[Preservation audit](triage_evidence/rpc502_vm_handoff_delivery.json), [scoped gates](triage_evidence/rpc502_vm_handoff_quality_gates.json), [publication verifier](triage_evidence/verify_rpc502_vm_handoff_publication.py). Full-goal completion remains false.
