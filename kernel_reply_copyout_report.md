# Matching-kernel reply copyout, consumption and map-context ABI

The kext's reply OOL0 copyout reaches exact `_vm_map_copyout` at `0xfffffe000bdd1574`. Its original wrapper reads the u64 extent from copy-object+`0x20` and requests consumption. For a type3 object, successful byte copying reaches payload-pointer clearing, a payload-release call, copy-header zeroing and a copy-header-release call. Allocation and byte-copy errors return before this consumption sequence. This establishes the matching binary's conditional ownership protocol; native VM and allocator effects remain unknown. [KC1-KC6]

The other-map branch also exposes a 24-byte context result through X8. Original enter/restore helpers now execute in the private model, with only their lower map-switch leaf modeled. Twelve paired cases preserve the saved map and balance the inspected map reference increment/decrement. The actual received copy type and a joined daemon-to-kext transaction remain unknown. [KC2-KC8]

## Assumption register

| ID | Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| KC1 | The original hash-pinned collection and prior kext bindings are the intended static build | Addresses, exact symbols, wrappers and call association | Rehash originals, recapture all ranges and resolve slots; verify runtime module pairing separately |
| KC2 | Copy objects satisfy original zone/range checks and the declared type3 preconditions | Copyout/discard paths | Observe actual copy allocation/type/metadata; native descriptor conversion is not executed here |
| KC3 | Private map/thread state is valid and remains stable across the inspected operations | Current-map selection, reference changes and context save/restore | Observe native thread/map state and concurrent writers; tests supply no concurrent mutation |
| KC4 | Allocation, byte-copy, map removal, locking and lower map-switch effects match their explicit models | Mapped bytes, rollback and final map state | Substitute native outcomes and partial-copy behavior; failed-copy models write no payload bytes |
| KC5 | Release callbacks return normally | Control after release requests | Recover full allocator/zone retirement; no real allocation is freed by these tests |
| KC6 | The zone-view size is 48 bytes in these fixtures | Modeled header zeroing and header-release arguments | Read the native zone-view+`0x34`; actual runtime size and complete allocation extent remain unknown |
| KC7 | Map+`0xb8` is null; private pending-work flags are zero | Tested context-helper paths and zero auxiliary result | Trace non-null associated objects and pending-work paths, including their independent references |
| KC8 | Independent original-code replay and effect/ownership oracles apply to the finite fixtures | Counts, copied bytes and local ownership witnesses | Rebuild source, replay every read/write, reconstruct every effect from fresh arguments; native reachability is separate |

Primary evidence: original collection `/Users/___/Downloads/fpx/img4_dump/kernelcache.macho`, SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. [Source capture](triage_evidence/kernel_reply_copyout_source.json) retains eight compiler-bounded functions /1,282 instructions, 18 exact role checks and original nlist records. Release-function bodies are captured for provenance but their effects are modeled. `_copyout` and `_bzero` are exact symbols; descriptive names for stripped helpers denote recovered roles, not exact symbols. [KC1,KC5]

## Cross-layer handoff and object representation

The existing [kext VM report](kext_port_vm_report.md) establishes the local call at `0xfffffe000a60d61c`: `kernel_vm_map_copyout(*kernel_map,&FP[-0x80],C[0x90])`. OOL1 at C+`0x40` is optionally discarded on the inspected normal path at `...a6123cc`; copyout-error cleanup also discards OOL0. The [reply ABI report](rpc502_reply_bridge_report.md) establishes how the generated client returns the two address/count pairs. These are separate established slices; this increment executes the kernel VM functions rather than joining the obfuscated caller to native transport. [KC1,KC2]

```text
daemon user OOL regions
        |
        | native conversion / actual copy type: unresolved
        v
kext reply outputs -> OOL0 copy object -> exported copyout (consume=1)
                                           |
                                    type3 copy helper
                                  /                   \
                             copy success          allocation/copy error
                                  |                   |
                         consumption requests    preserve copy object
                                  |                   |
                         mapped VA -> record0    caller discard route

OOL1 copy object -> inspected optional discard route
```

| Copy-object field | Extent | Observed role |
| --- | --- | --- |
| +`0x00` | 8 bytes | Payload pointer, authenticated with modifier incorporating object address and `0xb7af` |
| +`0x10` | 8 bytes | Must be zero for this type3 helper |
| +`0x20` | 8 bytes | Object extent; wrapper forwards the complete u64 |
| +`0x2d` | 1 byte | Type selector3 |
| +`0x2e`, bit0 | 1 bit | Required by this helper when extent exceeds 32768 bytes |

The four positive extents tested are 1,37,32768 and32769 bytes. The last uses bit0=1; its production by an ordinary daemon reply is not established. The Mach reply extent is u32, while this VM object field is u64; equality and object origin require the missing native conversion contract. [KC2,KC8]

| Original site | Contract |
| --- | --- |
| `0xfffffe000bdd1578`-`...1590` | Null copy: write output address0 and return0; otherwise load object extent and pass consume=1 |
| `0xfffffe000bdcb3ec`-`...b3f4` | Internal mapper requires explicit extent == object extent; mismatch returns5 and output0 |
| `0xfffffe000bdcb400`-`...b414` | Type3 dispatch; helper receives allocation-mode0 and the mapper's consumption flag |
| `0xfffffe000bdcbe3c` | Allocation call; its nonzero result is propagated |
| `0xfffffe000bdcbd44` / `...be54` | `_copyout(payload,mapped_address,extent)`, other-map / current-map branch |
| `0xfffffe000bdcbe5c` | Successful-copy consumption gate: zero flag skips object release |
| `0xfffffe000bdcbf0c` / `...bf1c` | Clear payload pointer, then request payload release |
| `0xfffffe000bdcbf38` / `...bf4c` | Zero header using zone-view size, then request header release |
| `0xfffffe000bdc64e8` / `...64f4` | Type3 discard clears payload pointer before its payload-release call |

For private page shift14 and page-aligned allocation output B, the allocation extent is `R = (N+16383) & ~16383` bytes in the non-wrapping tested domain. The allocation boundary receives `(map,&address,R,0,0x6000000000000000,0,0,0)` when map equals the supplied `kernel_map` cell; its first three stack words are3,7,1. These are raw ABI values, not a recovered complete allocation-policy type. [KC3,KC4,KC8]

## Outcome and ownership channels

| Case | Returned u32 | Address output | Copy-object protocol |
| --- | ---: | --- | --- |
| Exported copyout, null copy | 0 | 0 | No release call |
| Allocation model returns6 | 6 | 0 | Object remains unchanged |
| `_copyout` model returns5 | 1 | 0 after cleanup | Mapping-removal request; object remains unchanged |
| Successful exported copyout | 0 | Allocated address | Payload pointer cleared; payload and header release requested |
| Successful internal consume=0 | 0 | Allocated address | Object remains unchanged; caller retains its obligation |
| Internal explicit-extent mismatch | 5 | 0 | Object remains unchanged |
| Type3 discard | Void; return register not a status contract | Not an output of this call | Payload pointer cleared; payload and header release requested |

The byte-copy failure cleanup requests removal of `[B,B+R)` in the aligned fixtures and clears the address output at `...bdcbefc`. It then returns1. Failed-copy cases deliberately model zero copied bytes; native partial writes are unknown. The release requests at `...bdcbf1c` and `...bdc64f4` pass descriptor `0xfffffe0007f8bfb0`, payload pointer and extent. Header-release requests pass the zone pair, copy object and zone-view size. These original caller arguments do not prove the complete allocator implementation or actual retirement. [KC4-KC6,KC8]

The kext caller's stale C+`0x90` bits therefore cannot establish a live copy object after successful consuming copyout. Conversely, a failed type3 copyout does not consume it in the inspected control path, consistent with the separately recovered caller discard. Actual double-discard, leak, or native reference-balance conclusions are not established. The mapped VM region has a separate lifetime from the retired copy wrapper; close/unwire/free of that region remains unresolved. [KC1-KC6]

## X8 context-result ABI and map references

The type3 helper compares destination map against authenticated thread+`0x428`. An unequal-map path validates the map's supplied range/zone metadata and increments its u32 reference at+`0x88`. The inspected paired decrement restores the initial value3 after byte copying. Current-map paths skip that retain/release pair. Counts are conditional on stable state and exclude native concurrency. [KC2,KC3]

At `0xfffffe000bdcbca0`, X8 receives the address of a 24-byte caller-stack context record. The call at `...bdcbcac` invokes original helper `0xfffffe000bdcc234`, with X0=destination map and W1=0. The original restore helper is `0xfffffe000bdcc374`, called at `...bdcbd64` with X0=context pointer. [KC3,KC7]

| Context offset | Extent | Original producer / consumer |
| --- | --- | --- |
| +0 | 8 bytes | Enter saves authenticated previous thread map at `...bdcc340`; restore reads it at `...bdcc38c` |
| +8 | 8 bytes | Enter saves value derived from destination-map+`0xb8`; zero in these fixtures; restore has separate nonzero-object handling |
| +16 | 4 bytes | Enter saves incoming W1 at `...bdcc344`; value0 here |
| +20 | 4 bytes | Enter writes zero at `...bdcc344` |

Both original helpers call lower leaf `0xfffffe000be63ea0`. Its modeled effect changes only the private thread-map field to the requested map; native switching, scheduling and hardware translation effects are not executed. The original helpers also update thread+`0x1c8`; fixtures provide a private pending-work record with flag byte0. The non-null map+`0xb8` object path and pending-work callbacks remain unexecuted. The restore slice does not read context+16/+20; their wider semantics remain unknown. [KC3,KC4,KC7]

## Verification and bounded continuation

[Profiles](triage_evidence/kernel_reply_copyout_profiles.json) retain42 cases: eight each of successful exported copyout, allocation failure, byte-copy failure and successful non-consuming copyout; four type3 discards; two null-object cases; and four explicit-extent mismatches. [Checks](triage_evidence/kernel_reply_copyout_checks.json) freshly recapture the original source and independently replay6,845 visits,1,917 reads /13,813 bytes,1,449 writes /11,064 bytes,176 declared callback models and42 final boundaries. Seventy-six private effect patches /263,260 bytes are reconstructed from fresh registers and memory. [KC8]

The separate ownership/effect oracle checks12 payload/header release pairs,12 original context pairs and24-byte saved records, eight mapping-cleanup requests,262,300 successfully copied payload bytes, unchanged copy objects on errors/non-consuming success, final map reference3, and restored thread map. Twelve release pairs consist of eight consuming copyout successes plus four standalone discards; these are distinct test cases, not two releases of the same live object. Native copy type, actual module pairing, successful application execution and complete FairPlay round trip remain unknown. [KC1-KC8]

Reproduce in order from the extracted directory:

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_reply_copyout.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_reply_copyout.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_reply_copyout.py
```

Time is O(captured bytes + source visits + copied effect bytes); space is O(private RAM + retained journals). No target process, native VM, IPC, allocator release, hardware PAC, IDB mutation or saved-memory update is performed. No SMT theorem or full-domain execution claim is made. The full investigation remains active. [KC1-KC8]

| Impact | Remaining bounded interface | Evidence needed |
| --- | --- | --- |
| High | Actual daemon reply -> copy-object type/extent | Recover native send copyin and transport handoff without supplying copy objects as fixtures |
| High | Mapped-region lifetime after installation in record0 | Trace successful context publication, page callbacks, close, unwire and VM deallocation |
| High | Other copy representations | Recover type2 entry-list consumption/error paths; current type3 result does not generalize to every object |
| Medium | Context-associated object and pending work | Trace non-null map+`0xb8` references, context epochs and scheduling callbacks |
| Medium | Allocator retirement and native metadata | Recover release callees' complete contracts and actual zone-view size |
| Low | Copy-error statistics | Original other-map failure increments `0xfffffe000cb810f0`; current-map failure does not traverse that counter store |

- QG1: Pass. Factual interface and ownership analysis.
- QG2: Pass. KC1-KC8 identify assumptions, dependencies and falsification probes.
- QG3: Pass for the matching-kernel type3 copyout/discard increment; other types and native joins remain open.
- QG4: Pass. u32/u64 fields, byte extents, alignment domain, record size, exact counts and complexity are explicit.
- QG5: Pass for scope. Consume0/1, null, mismatch, allocation/copy failure, other/current map, distinct discard cases and modeled retirement are separated.
- QG6: Pass. Original hashes/functions/symbols, exact role checks, fresh replay and independently reconstructed effects are retained.
- QG7: Pass. Impact-labeled continuation identifies immediate remaining contracts without generalizing the finite fixtures.

Publication checks: [preservation](triage_evidence/kernel_reply_copyout_delivery.json), [scoped gates](triage_evidence/kernel_reply_copyout_quality_gates.json).
