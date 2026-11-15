# FPHashTable reclamation and the conditional FPSecureTunnel free request

Marker-unequal cleanup changes the matched entry to a tombstone through `0xfffffe000a5aec24`, then calls the backward-reclamation helper at `0xfffffe000a616860`. The entry writer stores a raw state, key representation and payload; it has no status output. The reclamation helper publishes a raw status in its record. Cleanup issues `_IOFreeTypeImpl` with the saved entry+16 payload and a `site.FPSecureTunnel` descriptor only when the tested status equals `0x31ae0066` and that payload is nonzero. The descriptor records 120 B. This establishes the requested free ABI, not the native allocation identity, unique ownership or actual deallocation of the payload. [HR1-HR8; HR-A1-HR-A8]

The source distinguishes tombstone creation from empty-slot reclamation. The entry writer increments header word +0 for empty-to-occupied, decrements it for tombstone-to-empty, and leaves it unchanged for every other old/new state combination. Therefore the current occupied-to-tombstone step does not decrement it. If the following entry is empty, the second helper walks backward and clears a trailing run of tombstones. Each cleared tombstone decrements the word once. These transitions support a used-slot interpretation that includes tombstones; the global invariant remains unknown until the producer/update callers are recovered. [HR2-HR6; HR-A3-HR-A7]

Primary evidence: [original functions, caller region, fixups and descriptor](triage_evidence/userclient_hash_table_reclamation_checks.json.zst), [source obligations and independent reference replays](triage_evidence/userclient_hash_table_reclamation_audit.json.zst), [extractor](triage_evidence/recover_userclient_hash_table_reclamation.py), [auditor](triage_evidence/audit_userclient_hash_table_reclamation.py), [publication verifier](triage_evidence/verify_userclient_hash_table_reclamation_publication.py). Context: [lookup](userclient_hash_table_lookup_report.md), [initializer](userclient_hash_table_initializer_report.md), [shared-holder bootstrap](userclient_hash_table_bootstrap_report.md), [UIDList cleanup](userclient_uidlist_cleanup_report.md), [context lifecycle](userclient_context_lifecycle_report.md), [descriptor/task flow](context_descriptor_task_flow_report.md). Original bytes and retained receipts suffice; no new IDA access, IDB mutation or native target API call is performed.

```text
second lookup: status success AND found bit0
  true -> matched entry
          -> writer: state=TOMBSTONE, key=KEY0, payload=0
          -> reclaim(index, capacity, array, header)
             next entry not EMPTY -> success; leave tombstones
             next entry EMPTY     -> walk backward
                EMPTY/OCCUPIED -> stop successfully
                other state    -> writer: EMPTY, KEY0, payload=0
                                  -> previous index, wrap, bounded repeat
          -> reclamation status
  false -> second lookup status

tested status == 0x31ae0066 AND saved entry+16 != 0
  true -> _IOFreeTypeImpl(site.FPSecureTunnel descriptor, saved payload)
  either condition false -> skip this free
  -> existing UIDList-node free path -> saved-successor continuation
```

The saved entry+16 word comes from the first confirmed lookup hit, before either entry update. Clearing an entry's payload does not erase that saved caller word. The lookup report's unknown native payload type/ownership is refined here to a conditional descriptor-specific free request; producer identity and native ownership remain unknown. [HR1,HR3,HR7,HR8; HR-A5-HR-A8]

## Source and independent validation

| Quantity | Verified value |
| --- | --- |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original collection SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Complete entry writer | 124 instructions / 496 B, `0xfffffe000a5aec24..0xfffffe000a5aee14` |
| Complete reclaimer | 318 instructions / 1272 B, `0xfffffe000a616860..0xfffffe000a616d58` |
| Caller region | 201 instructions / 804 B, `0xfffffe000a6270dc..0xfffffe000a627400`; independently matched to the prior full destroy-function capture |
| Source partition | 603 modeled instructions / 2412 B: writer112, reclaimer301, caller190; 25 transfers / 100 B; 15 remaining PAC/BTI instructions |
| Models and static data | 31 spans, six 256 B arrays, nine bank rules / 2304 byte-input cases, six pool pointers, 18 branch pointers and one 64 B typed descriptor |
| New source obligations | 36 nonvacuous UNSAT queries; 3149 instruction instances; every selected PC covered |
| Entry-writer replay | 49 cases / 5104 source instruction instances, including all 16 combinations of four old/new state profiles at counters 0, 1 and 0xffffffff, plus a null entry |
| Reclamation replay | 15 cases / 29,763 source instruction instances, including 140 nested calls to the actual lifted entry writer |
| Replay source coverage | 412 distinct writer/reclaimer PCs; alternate retag instructions are separately source-proved |
| Predecessor checks | Four re-solved source queries: saved payload/second call, second status/found gate, tombstone/probe successor and lookup frame restoration |
| Altered evidence | Four rejections: instruction byte, bank byte, branch target and typed-free size |
| Checks decoded SHA-256 | `831f3e6b1a7283f2b1b6a87df5a99a1bb627f3552e0c72da0c65d7e88b6757c0` |
| Audit decoded SHA-256 | `c3bea10d4cdbc608f9f03d208249ea2cb94e30f91a16c2b146f40d59e968aab4` |

The source/reference replays compare exact array bytes, counter values, raw status and cleared-index order, and check preserved entry padding and restored frames. Cases include no-op boundaries, backward wrap, a 127-tombstone run, unknown states, modular counter underflow, capacities 1/3/128 and a null array. They are synthetic source interpretation against private arrays, not native execution. The proof model uses original left-bank reads and an explicit right-bank composition lemma, independently checked for all 256 inputs of each of nine original bank rules. Each query freezes its own bank-lemma applications and any codec rewrite. An additional source obligation proves that the nested writer record inside the reclaimer frame satisfies the writer's actual 16 B frame-separation contract; every concrete replay checks its corresponding storage premises. [HR1-HR8; HR-A1-HR-A6]

## Exact routines, calls and source locations

| Evidence | Original source | Recovered role |
| --- | --- | --- |
| HR1 | `0xfffffe000a6270e0..0xfffffe000a6271e8` | Selected entry address and first writer record/call |
| HR2 | `0xfffffe000a5aec28..0xfffffe000a5aede0` | Writer environment, token/null gate, exact counter-adjustment predicates |
| HR3 | `0xfffffe000a5aede8..0xfffffe000a5aee10` | Raw key/payload/state stores and 16 B leaf-frame restoration |
| HR4 | `0xfffffe000a6271ec..0xfffffe000a6272f4`; `0xfffffe000a616988..0xfffffe000a616af4` | Reclaimer caller/decoder join, null-array gate, wrapped following-entry test and capacity preparation |
| HR5 | `0xfffffe000a616afc..0xfffffe000a616bfc` | Backward cursor, nested codec key and empty/occupied stop condition |
| HR6 | `0xfffffe000a616c00..0xfffffe000a616d18` | Nested empty-entry request, backward wrap/budget and raw status output |
| HR7 | `0xfffffe000a6272f8..0xfffffe000a62735c` | Raw output load and status/payload free predicate |
| HR8 | `0xfffffe000a627364..0xfffffe000a6273f8`; `0xfffffe000a616d1c..0xfffffe000a616d54` | Typed-free request, node-free continuation, reclaimer canary/epilogue/failure path |

| Call site | Original pointer binding | IA modifier |
| --- | --- | --- |
| Entry writer, `0xfffffe000a6271e8` | Table index 0xf5d, slot `0xfffffe000847aa08` -> `0xfffffe000a5aec24` | 0x3936 |
| Reclaimer, `0xfffffe000a6272f4` | Index 0xf56, slot `0xfffffe000847a9d0` -> `0xfffffe000a616860` | 0xaf1c |
| Nested entry writer, `0xfffffe000a616ca8` | Same 0xf5d slot and writer target | 0x3936 |
| Typed free, `0xfffffe000a6273e8` | Index 0xf2b, slot `0xfffffe000847a878` -> exact `_IOFreeTypeImpl`, `0xfffffe000c4ba368` | 0x4d6a |
| Typed-free descriptor load | Pool index 0x117, slot `0xfffffe00084727b8` -> `0xfffffe000847bf60` | Unauthenticated data-pointer fixup |

The two update call sites use the U bank pair with key 0xef and constant 0x61; additives 0xefc and 0xef5 select their distinct targets. The nested writer uses V/0x6d/0x13 with additive 0xf4a. The free uses V/0x98/0x95 with additive 0xe96; its descriptor uses T/0x3e/0x54 with additive 0xc3. All original chained memberships, pointer words, diversity and targets are frozen separately. No recovered internal token is classified as an external IOKit selector. [HR1-HR8; HR-A1,HR-A2]

| Internal root | Original pool binding |
| --- | --- |
| Writer and reclaimer branch tables | Index 0x33, slot `0xfffffe0008472098`, bias -12 -> `0xfffffe0008472f20` |
| Reclaimer controller A | Index 0x1a8, slot `0xfffffe0008472c40`, bias -4 -> `0xfffffe000ccc3328` |
| Reclaimer controller B | Index 0x1c, slot `0xfffffe0008471fe0`, bias -4 -> `0xfffffe000ccc32f8` |

## Entry-writer record and exact transitions

For 48 B record R in X0, the source codec is `K64=((R XOR 0x2a4f38d70e12cee6)*0x91c952ff) mod 2^64`, with K32=low32(K64). The current token is 0xc28. A null entry pointer selects the ordinary leaf return after controller updates, with no entry or header store. A nonnull entry selects the following operations. [HR1-HR3; HR-A2-HR-A5]

| Record offset | Width | Meaning |
| --- | --- | --- |
| +0 | 8 B | Entry pointer |
| +8 | 4 B | Encoded token; subtract K32 to recover 0xc28 |
| +0x0c | 4 B | No writer read/store |
| +0x10 | 8 B | New raw payload |
| +0x18 | 8 B | Header pointer used only on counter-adjusting paths |
| +0x20 | 4 B | Encoded state; subtract K32 to recover new state |
| +0x24 | 4 B | No writer read/store |
| +0x28 | 8 B | Encoded key representation; add K64 to recover new key word |

| Old entry state | Requested state | Header word +0 delta modulo 2^32 |
| --- | --- | --- |
| Empty `0x629f8775` | Occupied `0x629f8777` | +1 |
| Tombstone `0x629f8776` | Empty `0x629f8775` | -1 |
| Every other old/new u32 combination | Any | 0 |

After the selected counter path, the writer stores the decoded raw key at entry+8, raw payload at +16 and decoded u32 state at +0. Bytes +4..+7 remain unchanged. Counter arithmetic has no underflow/overflow check in this function; these are exact modular results, not a claim that every counter value is valid in a populated native table. The function has no output status slot and no W0 success contract is inferred. [HR2,HR3; HR-A3,HR-A5-HR-A7]

Cleanup's first record is at SP+0x90. Its source-produced state decodes to TOMBSTONE, key word to `KEY0=0x1ee45f68039f9913` and payload to zero. The preceding lookup establishes the occupied-key hit; under unchanged entry state this is an occupied-to-tombstone transition with delta zero. The nested reclamation record requests EMPTY, the same KEY0 and payload zero. For an actual tombstone that changes the header counter by -1. KEY0 is the lookup representation of key zero; it is not a recovered cryptographic secret. [HR1-HR6; HR-A3-HR-A7]

## Reclamation record, alignment and loop

The 40 B outer record R uses `K32=low32((R XOR 0x0c92091678856dd2)*0x40d18915)`. Its current token is 0x559. The caller's different pre-multiply expression agrees with the helper under the 8 B record-alignment premise; the current R=SP+0x90 is 16 B aligned from the stack ABI. The source proof checks the pre-multiply low32 equality and explicitly applies it through the multiplication. The helper consumes W13 before overwriting that register, so no unproved high32 equivalence is used. [HR4; HR-A2,HR-A5]

| Offset | Width | Token0x559 interpretation |
| --- | --- | --- |
| +0 | 8 B | Header pointer for nested entry writers |
| +8 | 4 B | Encoded index; `index=(word+K32+0xe7a61627) mod 2^32` |
| +0x0c | 4 B | Encoded token; subtract K32 to recover 0x559 |
| +0x10 | 4 B | Encoded capacity; `N=(word-K32-0x35f2763e) mod 2^32` |
| +0x14 | 4 B | No helper read/store |
| +0x18 | 8 B | Entry-array pointer |
| +0x20 | 4 B | Raw status output |
| +0x24 | 4 B | No helper read/store |

For a valid index i<N, the helper first inspects following index `j=0 if i+1==N else i+1`. If that entry is not EMPTY, it returns success without changing entries. If it is EMPTY, it begins at i and walks backward. The stop test `(state OR 2)==0x629f8777` is exactly true for EMPTY or OCCUPIED. Every other state is passed to the writer with new EMPTY/KEY0/zero fields. Only a TOMBSTONE old state causes the writer's counter decrement. [HR4-HR6; HR-A3-HR-A6]

```text
reclaim(i, N, entries):              // ordinary-return model; 0 <= i < N
    if array_pointer == 0: return NULL_ARRAY
    if entries[(i+1) mod N].state != EMPTY: return SUCCESS
    cursor = i
    iteration = 1
    while entries[cursor].state not in {EMPTY, OCCUPIED}:
        writer(entries[cursor], EMPTY, KEY0, 0, header)
        cursor = N-1 if cursor == 0 else cursor-1
        iteration = iteration+1
        if iteration > N: return BUDGET_EXHAUSTED
    return SUCCESS
```

The exact source comparison is proved for u32 iteration values below 0xffffffff. The constructor's N=128 profile satisfies that bound. Under a stable, nonaliasing array, the previously observed following EMPTY entry forms a backward-scan boundary, so at most N-1 entries precede it. The 127-tombstone replay checks the extreme constructor-sized run and all nested mutations. The generic budget-failure word is retained without claiming a native failing transaction. This loop is O(N) time and O(1) auxiliary storage apart from fixed frames; its writes are limited to cleared entries, the header counter, records/frames and controller cells under the stated premises. [HR4-HR6; HR-A3-HR-A6]

| Raw reclamation outcome | Status at R+0x20 |
| --- | --- |
| Null array for token0x559 | `0xce515bbf` |
| No reclamation needed, stop boundary or completed backward scan | `0x31ae0066` |
| Iteration budget exceeded | `0xce515bd9` |

No errno meaning is assigned. The status is a memory output, stored before the canary check and authenticated return. A status word alone is not proof of ordinary return. Zero capacity, out-of-range indexes, other tokens and concurrent mutation are outside the coherent constructor-table contract. [HR4-HR8; HR-A2-HR-A6]

## Payload free request and node continuation

At `0xfffffe000a627334` cleanup compares the tested raw status with `0x31ae0066`. It loads X1 from saved SP+0x18, then uses CCMP/CSET to skip the free for either a different status or a zero payload. Exact branch selection is proved for all status32/payload64 values. The tested status is the second lookup's word on its miss/failure route, or the reclaimer's R+0x20 word after the update route. The prior lookup gate and frame obligations are re-solved separately. [HR7; HR-A2,HR-A5,HR-A8] The final free gate does not retest the found byte or whether reclamation ran. A candidate-success word on the second lookup's alternate route is still tested as that raw success word; its native occurrence after the first hit is not established without a coherent cross-call epoch.

| Gate or interface | Exact recovered binding |
| --- | --- |
| Status success and payload nonzero | Table index 0x4fa -> `0xfffffe000a627360`, modifier 0x709b |
| Other status or payload zero | Index 0x518 -> `0xfffffe000a626920`, modifier 0x709b |
| Free call arguments | X0=`0xfffffe000847bf60`, X1=unchanged saved entry+16 payload |
| Descriptor | `site.FPSecureTunnel`; empty signature; flags u32 0x6c; size u32 120 B at +0x2c; original name/signature pointer chains retained |
| Kernel adapter | `0xfffffe000c4ba368`: BTI C, then branch at `0xfffffe000c4ba36c` to `0xfffffe000bcff010`; no argument transformation in this adapter |
| Ordinary free return | Index 0x39b -> `0xfffffe000a626920`, modifier 0x0678; restores controller pointers and joins the previously recovered UIDList-node free path |

The descriptor name is evidence for the type of free request. It does not prove the supplied value was allocated by the matching typed allocator, was exclusively owned, remained live, or was actually freed. Those require the payload producers and native lifetime evidence. The saved successor and eventual context-free continuation remain governed by the prior [UIDList cleanup](userclient_uidlist_cleanup_report.md) and [context lifecycle](userclient_context_lifecycle_report.md) contracts. [HR8; HR-A6-HR-A8]

## Environment, control and interface touch points

The entry writer has a 16 B leaf frame and ordinary RET. It updates u64 controller cells `0xfffffe000ccc33a0` and `0xfffffe000ccc32f8`. The reclaimer has a 224 B frame, preserves X19-X30, saves/checks the stack guard and returns with RETAB. Its root controller interface uses `0xfffffe000ccc3328` and `0xfffffe000ccc32f8`; original pointer-table evidence determines these addresses. Source proofs establish both frame restorations and the reclaimer's saved/fresh guard comparison. Guard mismatch branches from `0xfffffe000a616d30` to the call at `0xfffffe000a616d54`, targeting the previously frozen `___stack_chk_fail` stub. Hardware PAC success remains an explicit premise. [HR2,HR4-HR8; HR-A1,HR-A2,HR-A5,HR-A6]

For the selected entry/cursor address `a=P+24*i`, the ordinary array interpretation requires `(P XOR a)&0xffc0000000000000==0`. The alternate MOVK replaces the computed top 16 bits with 0xc8a2; that raw transform is separately proved. The model separates aligned frame, record, header and full nonwrapping array extent from each other and all five complete image VM regions, including zero-fill storage. The writable entry slot has an explicit 24 B separation premise as well. No valid native dereference of the alternate tag path is inferred. [HR1,HR5; HR-A4,HR-A5]

The complete entry writer has no external call. The complete reclaimer calls only that writer and the stack-failure stub; the selected cleanup region adds the typed-free request. No Mach trap, new incoming endpoint, outgoing port transfer or Mach-port emission location is established by this increment. The typed payload is not classified as a Mach port. Broader endpoints remain in the [Mach-port report](mach_ports_report.md). Serialization around shared table mutation, metadata coherence and native daemon-kext transactions remain unknown. [HR1-HR8; HR-A6-HR-A8]

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| HR-A1: Pinned original/normalized images and original fixup membership | Source identities, call targets, descriptor | Fresh full-function/region extraction, exact hashes, original pointer chains, altered-byte/target/size rejection |
| HR-A2: Tokens0xc28/0x559 and ordinary authenticated transfers | Current record decoders, branch composition and return | Three writer-record contexts, caller/helper codec equalities, original PAC modifiers, all 2304 bank inputs; other tokens/native PAC unknown |
| HR-A3: Positive coherent capacity, valid index and stable array/header | Backward policy and current deletion path | Constructor128 predecessor context, next/boundary guards, capacities1/3/128, long-run and wrap replays; producers/global counter invariant unknown |
| HR-A4: Iteration below 0xffffffff, no pointer wrap and ordinary tag path for array dereferences | Bounded scan and 24 B addressing | Universal predecessor/budget equations, maximum constructor run and separate alternate-retag equations |
| HR-A5: 16 B stack alignment, 8 B record/header/array alignment; disjoint valid storage and intact saved cells | Low32 caller codec join, alias reasoning, padding, fields and frame restoration | Nonvacuous alignment/separation premises, explicit entry extent, exact byte replays and saved-register checks; misaligned-record equality is not asserted |
| HR-A6: Exhaustive byte-bank identities and conservative per-PC controller values | Pointer bindings and source composition across internal calls | Original left reads, explicit right-bank rewrite receipts, complete finite identities and independent source-address checks; no native atomicity/locking claim |
| HR-A7: State/counter names describe recovered local transitions | Tombstone reclamation and used-slot interpretation | All-state predicates, 48 transition/counter cases, unknown-state and modular underflow replays; global invariant awaits producers |
| HR-A8: Descriptor-specific request does not prove native payload identity/ownership | FPSecureTunnel interpretation, cleanup lifetime and daemon correlation | Exact status/pointer gate, original descriptor/name chains and adapter; recover allocation/entry producers and correlated transactions before extending native claims |

## Bounded continuation

| Impact | Evidence target | Consequence / boundary |
| --- | --- | --- |
| High | Producers of the entry+16 value and matching FPSecureTunnel allocation requests | Establish allocation identity, field layout, sharing and lifetime relative to this conditional free |
| High | Node+4 key producers and occupied-entry insertion callers | Determine caller influence, key domain and the global header-counter invariant |
| High | Context/table serialization and holder lifetime | Establish which lookup/mutation/free observations belong to one coherent epoch; repeated lookup alone does not supply a lock |
| Medium | Full per-node/whole-list composition with existing context cleanup | Join the recovered branch contracts across populated list iterations without assuming native ownership or successful calls |
| Medium | Correlated fairplayd records, userclient callbacks and payload creation | Bind these kext-local transitions to actual daemon/kernel transactions and existing port endpoints |
| Low | Other internal tokens, malformed capacities and alternate tag dereferences | Extend helper domains with separate evidence; no such native reachability is established here |

## Quality gates

- **QG1**: Technical evidence and explicit scope only; no normative judgment is required.
- **QG2**: HR-A1-HR-A8 identify dependent claims and falsification probes.
- **QG3**: Current writer/reclaimer/free interfaces, data/control flow, exact locations, raw outputs, environment, Mach-port scope and remaining producers/lifetimes are covered for this increment; the full investigation remains active.
- **QG4**: Widths and extents are explicit: 48 B writer record, 40 B reclamation record, 24 B entry stride, 16 B header, 120 B typed-free descriptor size, 16/224 B frames, u32 counter and u64 pointers/keys. Exact modular arithmetic has no rounding term. Extraction/model construction is O(B+I+256R+query DAG), excluding solver search; each query has a 30 s limit. Finite replay is O(cases*N) time, with output space proportional to arrays and recorded paths.
- **QG5**: Occupied-to-tombstone versus tombstone-to-empty, local counter deltas versus global invariant, memory status versus return, null entry versus null array, alignment, padding, retag, native ownership and serialization are explicitly distinguished.
- **QG6**: Claims trace to original bytes/fixups, complete function capture, exact descriptor/name chains, nonvacuous reconstructed obligations, independently checked bank identities/reference replays and four predecessor queries. No external source or native result is fabricated.
- **QG7**: Ranked continuation covers payload allocation, key/insertion producers, counter invariant, serialized epochs, whole-list composition and daemon correlation; none is claimed complete here.

## FPSecureTunnel allocation follow-up

[The allocation and initialization report](secure_tunnel_allocation_report.md) binds the original call at 0xfffffe000a65a55c to a 120 B site.FPSecureTunnel descriptor, records its scratch publication and exact local byte layout, and compares the distinct allocation/free descriptors. Ten nonvacuous source obligations, 256 selector replays and 512 bank checks pass. Five object bytes are untouched by these stores. Whole dispatcher reachability, fallback convergence, entry+16 insertion lineage, native object identity/ownership and daemon transaction correlation remain unknown; no new Mach endpoint is established.
