# Produced type-2 copyout: extent guards, relocation and map-store frontier

The original exported copyout wrapper now consumes the exact type2 object produced in the [entry-copy analysis](kernel_vm_entry_copy_report.md). Original code distinguishes consuming and cloning paths, validates entries, relocates the selected entry, publishes the output address and enters map insertion. Successful destination-store insertion and copyout completion remain unknown. The retained destination map has no initialized store root, so execution stops before its packed-store search. Resolver/allocator/lock outcomes remain explicit models; no native mapping, payload delivery or FairPlay transaction is established. [TC1-TC8]

Evidence: [64 complete functions /11047 instructions](triage_evidence/kernel_type2_copyout_source.json), [14 private CPU cases](triage_evidence/kernel_type2_copyout_profiles.json), [independent replay and exact field oracles](triage_evidence/kernel_type2_copyout_checks.json). Collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Original collection and retained artifacts suffice. No new IDA access, IDB mutation, saved-memory update, native target execution or native IPC occurs.

## Functions, interfaces and original emission sites

Except for the established exported wrapper identity, names below describe inferred roles rather than exact original symbols. Capturing a complete body does not mean all its branches execute.

| Address | Identity / inferred role | Selected coverage |
|---|---|---|
| `0xfffffe000bdd1574` | Exported `_vm_map_copyout(map,outAddress,copy)` | Original wrapper in five cases |
| `0xfffffe000bdcb374` | Common copyout `(map,outAddress,copy,extent,flags)` | Exact-extent guard, type2 routing, relocation and errors |
| `0xfffffe000bdc7434` | Destination-range class selection and lower resolver adapter | Original kernel-map class 6 selection, ordinary errors and special fallback |
| `0xfffffe000bdde9ac` | Lower destination-range resolver | Complete source captured; body not executed; explicit frontier or result model |
| `0xfffffe000bdcbfcc` | Entry-list validation and aggregate-output adapter | Original one-entry path; selected original lower validators |
| `0xfffffe000bdc8760` | Per-entry admission/aggregate checks | Original selected NULL-object path |
| `0xfffffe000bdc8ba4` | Map-level admission/aggregate checks | Original selected fixture path |
| `0xfffffe000bdcc14c` | Unlink entries, mark exclusive, insert into map, then release wrapper | Original prefix through insertion call; release tail unexecuted |
| `0xfffffe000bde1300` | Map-entry insertion and store update | Original context construction, mapped-size update and accounting call; stops before search |
| `0xfffffe000bdcd914` | Associated-entry/map accounting helper | Selected NULL-object path returns |
| `0xfffffe000bddf0b0` | Packed-store vector search | Complete source captured; explicit pre-entry stop |
| `0xfffffe000bddf2c8` | Packed-store update continuation | Captured; unexecuted |
| `0xfffffe000be2fac0` | Entry release after insertion | Captured; unexecuted at held frontier |

| Original site | Data/control effect |
|---|---|
| `0xfffffe000bdd157c` / `...1580` | Load copy+0x20 logical extent / set raw flags 1 before common call |
| `0xfffffe000bdcb3f0` / `...b43c` | Compare requested extent to copy extent / zero output address on mismatch |
| `0xfffffe000bdcb56c` | Request destination interval through original range adapter |
| `0xfffffe000bdc7558` | Call lower resolver with eight register arguments |
| `0xfffffe000bdc755c` / `...7564` | Recognize result `0x2e` and enter fallback bounds logic |
| `0xfffffe000bdcb5a0` | Raw flags bit0 selects reuse versus clone path |
| `0xfffffe000bdcb610` / `...b6a0` | Store relocated start/end / normalized flags on reused entry |
| `0xfffffe000bdcb83c` / `...b8b0` | Request 48-byte wrapper /64-byte entry clone allocations |
| `0xfffffe000bdcb990` through `...b9b0` | Copy original entry and reset clone bookkeeping using original constant1 |
| `0xfffffe000bdcbb04` | Write output address before map insertion |
| `0xfffffe000bdcbb18` | Call original unlink/insertion pipeline |
| `0xfffffe000bdcc194` / `...c198` / `...c1a8` | Unlink entry / store exclusive word `0x30000` / increment thread nesting |
| `0xfffffe000bdcc1c8` | Pass entry into original map insertion |
| `0xfffffe000bde13a8` | Add interval width to map+0x20 |
| `0xfffffe000bde13e8` | Call packed-store search; explicit stop before body |

These are local kernel copy-object/map interfaces. No new Mach name, receive/send right or message emission is established. The kext's previously established OOL-copyout sites remain caller context; this increment starts at kernel copyout rather than resuming an authentic kext/daemon exchange. The historical zut capture remains unchanged and still ends at failed UserClient open. [TC2,TC8]

## Exact produced-state transfer

The source is case 4 of the [entry-copy profiles](triage_evidence/kernel_vm_entry_copy_profiles.json): a source-code-produced singleton type2 wrapper of logical extent 32769 bytes, plus the separately produced type3 descriptor1. The producer is independently replayed afresh. Every consumer case receives its exact complete 1048576-byte primary RAM image, both 4096-byte auxiliary pages and all declared image globals. Registers are initialized for separate calls; these are component handoffs, not native CPU or scheduling continuity. No private initial memory overlay changes the produced copy. [TC2,TC3]

The original entry has NULL associated object, flags `0x4110`, start/end covering49152 bytes and initial word 1. This establishes a structural entry-list representation without authentic backing VM-object bytes. The message's descriptor bits and the other produced copy remain byte-identical in all 14 consumer cases. [TC3,TC4]

```text
exact source-produced type2 object -> exported wrapper
  -> load logical extent, flags 1 -> common copyout
       +-> wrong explicit extent -> zero output -> return5
       +-> exact extent -> original destination class/range adapter
            -> lower resolver [stop or declared result]
                 +-> error -> return, preserve copy/output canary
                 +-> 0x2e -> original bounds fallback -> return3 in file-state epoch
                 +-> declared success -> original validation
                      +-> bit0=1: relocate produced entry
                      +-> bit0=0: allocate/copy/relocate separate entry
                      -> output-address store -> unlink -> exclusive entry
                      -> map-size update -> packed-store search [stop]
```

## Extent and range ABI

The wrapper reads the copy's exact u64 extent and sets raw flags 1. It does not accept a separate extent argument. The direct common-function probes supply explicit extents 0,32768 and32770, each unequal to the produced extent 32769. With raw flags 0 and 1, all six cases return5, zero only the first eight output bytes, preserve the other eight canary bytes and leave the copy/entry intact. No map lock or resolver call occurs in these cases. This is an exact-equality interface check, not an alignment comparison. [TC4,TC6]

For the matching extent, page shift14 means page size `2^14 = 16384 bytes`. The adapter receives interval width `ceil(32769/16384) * 16384 = 49152 bytes`, or `0xc000`; the wrapper retains logical extent `0x8001`. [TC4,TC6]

| Interface | Observed arguments |
|---|---|
| Common copyout from wrapper | `(declared_kernel_map, outAddress, produced_copy, 32769, 1)` |
| Destination-range adapter | `(map, 0, 49152, 0, 0x6000000000000000, outInterval)` |
| Lower resolver | `(map, 0xfffffe000cb80d60, 0, 0, 0x6000000000000000, 49152, 0, outInterval)` |
| List validation adapter | `(map, selected_copy, 0, outAggregate16, 0x1000)` |
| Unlink/insertion pipeline | `(map, selected_copy, declaredDestination, 0, 0x6000000000000000)` |
| Map insertion | `(map, selected_entry, declaredDestination, 0, 0x6000000000000000)` |

The high raw range flag selects class 6 from bits 60..62. Original code indexes the class bounds table beginning at `0xfffffe0007e69f90` and derives the lower state-block address `0xfffffe000cb80d60`. Neither address is a Mach port. The captured 96-byte bounds table is zero in the file. Original-file global words at `0xfffffe000cb50620` and `0xfffffe000cb0bc50` are also zero. Their actual runtime values and initialization producers remain unknown. [TC1,TC5]

| Declared lower result | Original selected continuation | Output / copy state |
|---|---|---|
| No model | Stop before lower resolver body | Canary and produced copy preserved |
| 3 | Return3 through error observation/unlock requests | Canary and copy preserved |
| `0xffffffff` | Return raw u32 `0xffffffff` | Canary and copy preserved |
| `0x2e` | Original fallback uses retained zero file bounds; returns3 | Canary and copy preserved |
| 0 with declared destination | Proceed through validation/relocation into held store frontier | Output written; insertion incomplete |

The success model writes only the supplied eight-byte interval output. It does not establish that the declared destination satisfies a live class range, reserve a native interval or initialize a store. In particular, a modeled success is not a consistency proof for the retained zero file bounds. The special fallback case exposes that environmental premise explicitly. [TC5,TC7]

## Reuse, cloning and held ownership state

For the selected input flags `0x4110`, original relocation adds the destination-minus-source delta to start/end. The 49152-byte width is preserved. Original flag normalization produces `0x5730`. With bit7 clear, the exercised arithmetic is `(((0x4110 | 0x1000) & u32(-0x2ff1)) | 0x730) & 0xfffffff9 = 0x5730`. All operands are32-bit bitvectors where indicated. [TC4,TC6]

| Raw common flags | Selected entry at frontier | Original produced copy |
|---|---|---|
| 1, from exported wrapper | Reused entry | Original list head/tail/count become zero |
| 3, direct probe | Reused entry | Same selected prefix behavior as flags 1 |
| 0, direct probe | Separate cloned entry | Original wrapper/entry remain byte-identical |
| 2, direct probe | Separate cloned entry | Same selected prefix behavior as flags0 |

Direct raw flags are declared component inputs; external caller control over these values is not established. Only the demonstrated bit0 decision and prefix equivalences are established. These cases do not prove that all remaining flags have no effect later in the complete routine. [TC4,TC8]

The cloning branch requests `(wrapper_zone,wrapper_aux,4)` and separately `(entry_zone,entry_aux,0x8004)`. Models return distinct private addresses; original instructions construct the 48-byte wrapper and copy/reset the 64-byte entry. The clone's original initializer is 1 from `0xfffffe000700dc38`. A different original constant at `0xfffffe000700dc68` is 8 and initializes the temporary validation record; it is not substituted for the entry initializer. [TC1,TC6,TC7]

At each successful-model frontier, original code has unlinked the selected entry from its wrapper, set its first u32 to `0x30000` and incremented thread+0x22c from 0 to 1. Original map+0x20 accounting becomes 49152, while map+0x48 store-root word and map+0x60 remain zero. The 24-byte search context is constructed from that root and local stack storage. No store search or insertion is executed, and the later entry release and wrapper zero/free tail are unexecuted. This is an intentionally held protocol state, not a completed ownership transfer or observed native leak. [TC3,TC6-TC8]

The output address store at `0xfffffe000bdcbb04` precedes the unlink/insertion pipeline. A nonzero value in that field therefore establishes neither successful return nor an installed mapping. The four held cases have no return status; their boundary X0 values are call arguments, not results. [TC6,TC8]

## Assumption register

| ID | Assumption / dependent claims | Stress test or falsification probe |
|---|---|---|
| TC1 | Hash-pinned collection functions/constants/fixups describe the intended build | Recapture all 64 functions, constants, global bytes and exact inherited callback slot; verify runtime build pairing separately |
| TC2 | Retained normalized reply and source-produced type2 case 4 define a relevant component input | Reconstruct producer afresh; join authentic FairPlay caller, namespace, transport and reply before complete exchange claims |
| TC3 | Exact RAM/auxiliary/global transfers and initialized call registers define stable private epochs | Compare all bytes and separate call setup; examine aliases, live state and concurrency independently |
| TC4 | NULL object, extent 32769, page shift14 and tested raw flags define this branch family | Cover non-NULL/tagged objects, alternate shifts/extents/flags and actual object provenance |
| TC5 | File-zero class bounds/globals and a declared kernel-map identity define only this environment | Recover boot/runtime writers and real bounds/resolver state; do not infer live availability from modeled success |
| TC6 | Observed layouts,32/64-bit arithmetic, source write order and held fields describe selected original prefixes | Verify exact field/aggregate/state oracles and continuation ordering; complete search/insertion/release before success/lifetime claims |
| TC7 | Lower resolver, zone allocation, locks and logical PAC provide stated outcomes | Independently derive effect records and allocator ABIs; replace models before native reservation, mapping or retirement claims |
| TC8 | Fourteen finite cases and the pre-search stop bound conclusions | Recover initialized destination store, actual resolver, insertion/release, non-NULL payload and authentic kext/daemon continuity |

## Verification and bounded continuation

Fourteen fresh CPU replays verify 3098 original instruction visits, 821 reads /6024 bytes, 862 writes /6644 bytes and all 14 final boundaries. They compare 14 complete primary RAM images /14680064 bytes, 28 auxiliary-region records and 112 global records. Sixty-three consumer frames,31 API models and four independently derived resolver patches /32 bytes pass. One fresh producer replay separately reconstructs the actual supplied type2 object. Nine components return and five stop at explicit frontiers: six extent rejections, two ordinary resolver errors, one fallback error, one lower-resolver stop and four store-search stops.

```text
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_type2_copyout.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_type2_copyout.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_type2_copyout.py
```

Recovery is O(image + captured bytes) time/space. Replay is O(visits + RAM + effects) time and O(image + RAM + journals) space; compressed snapshots add retained storage. Primary RAM is1048576 bytes per case; each auxiliary page is4096 bytes. All stated arithmetic is exact in the tested domain; no statistical or native-performance claim is made.

| Impact | Bounded continuation | Evidence it would add |
|---|---|---|
| High | Recover destination-map/store initialization and class-bounds writers | Replace the missing-root/file-zero environment premises |
| High | Continue genuine packed-store search, insertion and entry/wrapper release | Establish completed structural copyout and held-state unwind |
| High | Replace lower range resolver and establish non-NULL backing-object input | Actual membership/reservation and payload provenance |
| High | Resume authentic kext caller with established namespace/daemon reply | Cross-layer continuity beyond isolated CPU components |
| Medium | Other raw flags, shifts, conversion, tagged objects and contention | Extend ABI, error and ownership coverage beyond selected paths |

QG1: Factual technical analysis; no normative judgment required.
QG2: TC1-TC8 identify assumptions, dependent conclusions and falsification probes.
QG3: Scoped anonymous routine roles, call/store sites, type2 ABI, copy/data/control/environment and respective reporting updates are covered; full goal remains incomplete.
QG4: Exact widths, offsets, bitvector arithmetic, page/extent calculations, byte counts, costs and commands are reproducible.
QG5: Exact produced state versus modeled resolver, file bounds versus live state, reuse versus cloning, output store versus success, and held versus completed ownership are distinguished. Unexecuted paths remain unknown.
QG6: Original source/constants/globals/fixups, producer reconstruction, exact state journals, independent CPU/effect replay and field oracles provide primary provenance.
QG7: Impact-labelled continuation remains bounded to unresolved map, lifetime and FairPlay interfaces.

[Preservation](triage_evidence/kernel_type2_copyout_delivery.json), [scoped gates](triage_evidence/kernel_type2_copyout_quality_gates.json), [publication verifier](triage_evidence/verify_kernel_type2_copyout_publication.py). The full goal remains active.
