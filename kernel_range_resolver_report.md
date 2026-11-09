# Original range allocation, bitmap records and tagged lookup

The lower destination-range model is replaced by original execution for the tested paths. The retained file-zero class bounds produce status 3. With separately declared valid bounds, empty bucket state, cached random words and a record-zone result, original interval search, record construction, bitmap selection and copyout complete in four cases. Twenty later lookups execute the tagged-record path without API models. Native bounds initialization, allocator/lock/byte-move effects, entropy provenance, backing bytes, mappings and authentic FairPlay transport remain unknown. [RA1-RA8]

Evidence: [72 complete functions /12376 instructions and file cells](triage_evidence/kernel_range_resolver_source.json), [25 private CPU cases](triage_evidence/kernel_range_resolver_profiles.json), [independent CPU/effect replay and exact oracles](triage_evidence/kernel_range_resolver_checks.json). Original collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Original files suffice; no new IDA access, IDB mutation, saved-memory update, native target execution or native IPC occurs.

## Recovered interfaces and original sites

The following names are inferred roles, not exact original symbol identities. Full source capture does not mean all branches execute.

| Address | Inferred role | Selected evidence |
|---|---|---|
| `0xfffffe000bdde9ac` | Cached size-class/bitmap range allocator | Original eligibility, class selection, cached-random selection and result pair |
| `0xfffffe000bddee0c` | Pool reservation and allocation-record producer | Original empty-bucket path, forward interval search, header/list/store construction |
| `0xfffffe000bdde280` | Forward free-interval search | Original zero-bounds rejection and valid empty-map search |
| `0xfffffe000bdddbd8` | Reverse free-interval search | Complete source captured; unexecuted |
| `0xfffffe000bdc7434` | Class-bounds/allocator adapter and fallback routing | Original class 6 path and returns |
| `0xfffffe000bde1300` | Map-entry insertion with optional allocation record | Original non-NULL record-token path |
| `0xfffffe000bdc7274` | Candidate lookup with direct and tagged-record forms | Twenty original tagged/forward-scan cases |
| `0xfffffe000bddd5dc` | Packed-store position resolver | Original lookup execution; no position-result model |

| Original site | Observed request / publication |
|---|---|
| `0xfffffe000bddeabc` / `...eac0` | Compute class bucket offset / load cached record |
| `0xfffffe000bddeacc` | Call original pool/record producer on empty bucket |
| `0xfffffe000bddeed4` | Call forward interval search for a pool reservation |
| `0xfffffe000bddef5c` | Request record-zone allocation `(zone,aux,0x8004)` |
| `0xfffffe000bddef64` through `...efa4` | Construct base/class/order/bitmap/budget fields |
| `0xfffffe000bddf004` / `...f00c` | Construct compressed self-links / publish bucket head |
| `0xfffffe000bddf038` | Insert tagged pool record into original packed store |
| `0xfffffe000bddedcc` / `...eddc` | Load cached random word / store shifted next word |
| `0xfffffe000bddec40` / `...ec4c` | Clear selected bitmap bit / decrement budget byte |
| `0xfffffe000bdded64` | Store 16-byte `(address, allocation_record)` result |
| `0xfffffe000bdcbb18` | Forward result record through unlink/insertion pipeline |
| `0xfffffe000bdcc1c8` | Pass non-NULL record as fourth map-insertion argument |
| `0xfffffe000bdc738c` through `...73f4` | Decode tagged allocation record and secondary index |
| `0xfffffe000bdc7358` through `...7368` | Forward-scan tagged record's first candidate |

These are local kernel object/bookkeeping interfaces. The result record pointer, compressed record tag and candidate IDs are not Mach port names, rights or message dispositions. In particular, tag bit31 belongs to a packed-store record, not a Mach header. No new Mach emission or authentic daemon/kext exchange is established. The historical zut failed-open capture remains unchanged. [RA2,RA4,RA8]

## Exact input chain and evidence boundaries

Both the [source copy producer](kernel_vm_entry_copy_report.md) and the [map/root constructor](kernel_map_store_init_report.md) are independently reconstructed afresh. Five copyout cases receive the exact constructed primary RAM and auxiliary pages. Four add explicit class/bucket/random/zone fixtures; the first preserves the file-state environment. Twenty lookups transfer exact successful-consumer RAM/pages/globals. Separate call registers are initialized explicitly. These are component handoffs, not native scheduling or CPU continuity. [RA2,RA3]

| Input | Retained or declared value |
|---|---|
| Logical copy extent | 32769 bytes; NULL associated object |
| Map page shift | 14, or 16384 bytes per page |
| Class range in file-state case | Zero minimum / zero maximum |
| Class range in declared cases | R through R+1048576; R=`0x6500000000` |
| Class state block | `0xfffffe000cb80d60`; declared empty 448-byte observation extent |
| Bounds cells | `0xfffffe0007e69fe0`, class 6 pair |
| Cached random word | `0xfffffe000cb810e0`; four nonzero declared seeds |
| Record-zone pair | File cell `0xfffffe000caec380`; declared private zone/auxiliary pointers |
| Record observation address | `0xfffffe00010000c0`, supplied by the lower allocator model |

The record model supplies 64 zeroed bytes for the observation extent. The original producer constructs a 32-byte header; later insertion writes a secondary array through byte 63 in the selected cases. This establishes the exercised footprint, not an exact native zone allocation size. Native zone identity and capacity remain unknown. [RA3,RA4,RA7]

## Original interval reservation and result pair

The tested lower machine ABI is `(map, class_state, minimum, maximum, raw_flags, length, alignment_mask, out_pair)`. Raw flags are `0x6000000000000000`, length is 49152 bytes and alignment argument is 0. The original routine combines page alignment with the supplied mask and derives size class 16. [RA4,RA6]

| Interface | Selected original arguments |
|---|---|
| Range allocator | `(map,state,min,max,0x6000000000000000,49152,0,out_pair)` |
| Pool/record producer | `(map,state,min,max,0x6000000000000000,16,0x3fff)` |
| Forward interval search | `(map,min,max,0,1048576,0xfffff,out_interval)` |
| Final map insertion | `(map,entry,selected_address,allocation_record,0x6000000000000000)` |

With zero bounds, original interval search fails; the record producer returns NULL and the allocator returns 3. The exported copyout also returns 3, preserving the input copy, constructed empty store and output canary. No range-result model is used. This is a result for the retained file-zero epoch, not proof that a boot-initialized native kernel fails. [RA1,RA5]

With declared valid bounds, original interval search selects an aligned 1048576-byte pool spanning the declared range. The record producer publishes it in the packed store with a tagged record ID. The main allocator chooses an available 65536-byte slot and writes two u64 outputs: address followed by record pointer. The second output is not padding. Original caller frames carry it into insertion, where the entry receives the compressed record tag. [RA4,RA6]

```text
constructed map + original produced copy
  -> original class/range adapter -> original bitmap allocator
       -> empty bucket -> original interval search
       -> record allocation [zeroed-result model]
       -> original record/list construction and tagged pool insertion
       -> original cached-word selection and bitmap/budget update
       -> (selected address, record pointer)
       -> original entry relocation/insertion with record token
       -> forward-candidate index -> entry release -> wrapper cleanup -> return0
       -> real position resolver -> tagged-record candidate lookup
```

## Four distinct extents and selected arithmetic

| Layer | Extent | Meaning in this fixture |
|---|---|---|
| Logical copy | 32769 bytes | Exact payload extent retained by copy wrapper |
| Entry interval | 49152 bytes | `ceil(32769/16384) * 16384` |
| Allocator slot | 65536 bytes | `2^16`, derived size class |
| Reserved pool | 1048576 bytes | `2^(16+4)`, sixteen slots |

For this initially all-free record, the recovered selected arithmetic is:

```text
size_class = ceil_log2(max(length, page_bytes)) = 16
order = 4                 # selected size-class branch
slot_count = 1 << order = 16
pool_bytes = 1 << (size_class + order) = 1048576
slot = low32(cached_word) % 16
next_cached_word = cached_word >> 32
address = pool_base + (slot << 16)
bitmap = 0xffff & ~(1 << slot)
```

Four finite seeds validate selected slots 0,1,8 and15 and different next-cache values. This is not an exhaustive proof for arbitrary fragmented bitmaps, random-source outputs or size classes. The original SIMD/popcount/rank selection instructions execute; the random selection itself is not a model. The cached word is an explicit environmental fixture. [RA4-RA6]

| Cached u64 word | Slot | Address relative to R | Next cached word |
|---|---|---|---|
| `0x0000000012345678` | 8 | R+0x80000 | 0 |
| `0x0000000087654321` | 1 | R+0x10000 | 0 |
| `0xffffffffffffffff` | 15 | R+0xf0000 | `0xffffffff` |
| `0x0000000100000000` | 0 | R | 1 |

## Record representation and secondary candidate index

| Record offset | Selected original value / interpretation |
|---|---|
| +0x00 u64 | Class-state pointer |
| +0x08 s32 | Pool base scaled by65536; positive in these fixtures |
| +0x0c u8 | Size class 16 |
| +0x0d u8 | Slot count16 |
| +0x0e u8 | Low-nibble order 4; preserved upper nibble is zero under allocator premise |
| +0x0f u8 | Budget 11 after one selection; initialized12 |
| +0x10 u64 | Sixteen-bit bitmap with selected bit cleared |
| +0x18/+0x1c u32 | Compressed circular self-links, each `0x80040003` |
| +0x20 through +0x3f | Secondary forward-candidate array in these size-class cases |

Budget 11 differs from the bitmap's fifteen set bits. It must not be substituted for a generic bitmap popcount; the producer initially sets budget 12 while bitmap has sixteen bits set. Broader reserve/budget policy remains unknown. Bucket offset+0x10 holds the produced record pointer. [RA4,RA6]

Original pool insertion leaves root boundary keys0, R, R+1048576 and `UINT64_MAX`; the middle record is tagged `0x80040003`. Map head/tail still point to the actual VM entry, map accounting becomes 49152 and entry count becomes 1. The entry's u32 field +0x20 holds the same allocation-record tag; its interval is the selected address through address+49152, flags are `0x5730`, and its released lock word is `0x10000`. The consumed 48-byte wrapper is zeroed and passed to its release model. [RA4,RA6,RA7]

The secondary array is a forward-candidate index, not a per-slot occupancy bitmap. For selected slot s, original insertion writes entry ID `0x40001` into array indices 0 through `floor(s/2)` in these singleton cases. Remaining observed indices are zero. This prefix explains why lookups before the mapped entry can return its pointer with Boolean false. The maximum tested index 7 writes through record byte 63. [RA4,RA6]

The [earlier address-only model](kernel_map_store_init_report.md) supplied a zero allocation token, so its store contained a direct entry ID over the entry interval. Original bitmap allocation instead produces a tagged pool record, secondary index and nonzero token. Both consumer branches are valid source observations under their respective premises; only the latter demonstrates this original fast allocator's record-producing path. [RA2,RA5,RA6]

## Real tagged lookup and environmental branches

For each selected address D and E=D+49152, five lookup components execute original position resolution and candidate decoding without API/effect models:

| Query | Boolean | Candidate |
|---|---|---|
| D-1 | false | Non-NULL mapped entry |
| D | true | Mapped entry |
| D+32768 | true | Mapped entry |
| E-1 | true | Mapped entry |
| E | false | NULL |

There are twenty such components. The before-pool query in the slot0 case uses the forward-scan tagged-record branch; the other selected queries use the indexed tagged-record path. Pool coverage alone is therefore not entry membership. E-1 also concerns the rounded entry interval, not proof of additional logical payload bytes or access rights. [RA4,RA6,RA8]

The source contains further environment/control interfaces that remain unexecuted here:

| Source condition / site | Static contract / unresolved prerequisite |
|---|---|
| Map flag bits 3/8, raw flag mask `0x0200004000000080`, large length/alignment guards | Early raw result `0x2e`, selecting caller fallback; full fallback continuation remains untested here |
| Empty cached word, call `0xfffffe000be577f0` | Lower random-word source; native identity/provenance unknown |
| Word at `0xfffffe0007f8b5f0` greater than 18 | Alternate per-CPU random-provider path |
| Thread+0x1c8, thread+0x1b8, base at `0xfffffe000cb810f8` | Alternate path increments/decrements thread bookkeeping and derives a per-CPU object |
| Provider pointer from `0xfffffe0007f34e60`, slot+0x148, `BLRAA` at `...bddeb48` | Callback receives `(per_cpu_object, low8(selection_count), out_word)` with modifier `0xc231`; actual binding and hardware authentication unresolved |
| Budget reaches zero / pre-existing cached records / reverse search | Additional list movement, reuse and search paths captured but unexecuted |

These are kernel-owned fields and source-selected callbacks. External caller control over the cached word, provider or direct probe fields is not established. Native exclusion, preemption, entropy and concurrency semantics are not inferred from these private single-thread tests. [RA1,RA5,RA7,RA8]

## Assumption register

| ID | Assumption / dependent claims | Stress test or falsification probe |
|---|---|---|
| RA1 | Pinned functions and file cells describe the intended build | Recapture all 72 complete bodies and cells; verify actual runtime build separately |
| RA2 | Normalized copy producer and generic map constructor output are relevant component inputs | Reconstruct both afresh; establish boot kernel-map and authentic FairPlay caller/namespace/reply continuity |
| RA3 | Exact RAM/pages/globals and explicit class/bucket/cache/zone overlays define the tested epochs | Compare transfers and overlays byte-for-byte; recover actual runtime writers and identities |
| RA4 | NULL objects, size class 16, initially empty buckets and singleton cases bound the recovered representation | Test other classes, base encodings, fragmented/reused pools, multiple entries and non-NULL backing objects |
| RA5 | File-zero bounds and declared valid bounds/cache values remain distinct environmental premises | Recover boot class-state initialization and native random sources; do not treat private success/failure as native behavior |
| RA6 | Exact header/bitmap/prefix-index/root/node oracles and output-token joins compose these paths | Verify every frame and byte; cover all ordinals, record exhaustion, rollback, release and larger stores |
| RA7 | Record allocation, locks, byte moves, zero/free and logical PAC supply declared primitive outcomes | Rebuild argument-derived effects; recover native zone extent, ownership, mapping and authentication contracts |
| RA8 | Twenty-five finite cases do not exhaust range allocation or FairPlay interfaces | Continue fallback, reverse/provider paths, real boot state, backing bytes and complete kext/daemon transport |

## Reproduction, verification and bounded continuation

Twenty-five fresh CPU replays verify 7786 original instruction visits, 1915 reads /13021 bytes, 1200 writes /8904 bytes and all 25 returned boundaries. They compare 25 complete RAM images /26214400 bytes, 75 auxiliary-region records and 396 global records. Thirty-one API models remain, with no whole range-resolver or position-result model. Sixteen effect patches total `4 * (64 + 8 + 4 + 48) = 496 bytes`: record observation zeroing, key move, record move and wrapper zeroing in four successful cases. Two additional fresh replays reconstruct the source copy and map producers.

```text
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_range_resolver.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_range_resolver.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_range_resolver.py
```

Recovery/validation is O(image + captured bytes + visits + RAM + effects) time and O(image + source + RAM + journals) space. Each primary image is 1048576 bytes and each auxiliary page is 4096 bytes. Compressed snapshots add artifact storage. Arithmetic and byte counts above are exact within these fixtures; no statistical/native-performance claim is made.

| Impact | Bounded continuation | Additional evidence |
|---|---|---|
| High | Execute original caller fallback and rollback with zero/nonzero allocation token | Distinguish alternate reservation and error ownership contracts |
| High | Recover native class-state initialization and random-provider binding | Replace environmental identity/cache premises |
| High | Reuse/exhaust records and analyze candidate-index maintenance/removal | Extend lifetime semantics beyond first allocation |
| High | Recover non-NULL backing bytes and authentic FairPlay transport | Complete data provenance beyond structural copy objects |
| Medium | Other classes/ordinals, reverse search, multi-entry pools and per-CPU path | Extend arithmetic, search, callback and concurrency context |

QG1: Factual technical analysis; no normative judgment required.
QG2: RA1-RA8 identify premises, dependent conclusions and falsification probes.
QG3: Scoped routine roles, original call/store sites, address/record ABI, tagged representation, data/control/environment and respective reporting updates are covered; full goal remains incomplete.
QG4: Explicit widths, offsets, four distinct extents, bitvector/cache arithmetic, exact snapshot/effect counts, costs and commands are reproducible.
QG5: File versus declared bounds, 32-byte header versus 64-byte observation footprint, budget versus popcount, prefix candidates versus occupancy, zero versus nonzero tokens and private versus native behavior are distinguished.
QG6: Original hashes/functions/cells, fresh producer reconstruction, byte/field oracles, exact frames/journals and independent CPU/effect replay provide primary provenance.
QG7: Impact-labelled continuation remains bounded to unresolved allocator, environment, backing-object and FairPlay interfaces.

[Preservation](triage_evidence/kernel_range_resolver_delivery.json), [scoped gates](triage_evidence/kernel_range_resolver_quality_gates.json), [publication verifier](triage_evidence/verify_kernel_range_resolver_publication.py). The full goal remains active.
