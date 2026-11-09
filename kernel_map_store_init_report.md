# Original map construction, packed-store insertion and type-2 copyout

Original map/root construction now supplies the state needed to complete the prior [type2 insertion frontier](kernel_type2_copyout_report.md). Consuming and cloning copyout both execute original packed-store search/update, entry release and wrapper cleanup, then return zero. Seven later lookups execute the original position resolver without a position-result model. Source-copy discard preserves the distinct mapped clone. These are structural private-CPU results with NULL associated objects, modeled allocation/locks/range resolution/byte moves and declared destination identity. Native mappings, actual backing bytes, boot-time kernel-map provenance and a complete FairPlay exchange remain unknown. [MS1-MS8]

Evidence: [69 complete functions /11322 instructions and reference inventory](triage_evidence/kernel_map_store_init_source.json), [17 private cases](triage_evidence/kernel_map_store_init_profiles.json), [fresh independent replay and exact oracles](triage_evidence/kernel_map_store_init_checks.json). Original collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Original files suffice. No new IDA access, IDB mutation, saved-memory update, native target execution or native IPC occurs.

## Original identities and interfaces

The wrapper and byte-move aliases below are established by original nlist records. Other names are inferred roles. Complete body capture does not imply complete branch coverage.

| Address | Identity / inferred role | Selected coverage |
|---|---|---|
| `0xfffffe000bdc6eac` | Exact `_vm_map_create` and `_vm_map_create_external` aliases | Original three-argument wrapper |
| `0xfffffe000bdc6ebc` | Shared map constructor | Four cases, NULL associated pointer, shifts 12/14 and flags 0/3/4/16 |
| `0xfffffe000bddd56c` | Optional auxiliary-store initialization | Original selected flag 16 path with lower allocation model |
| `0xfffffe000bdd1574` / `...bdcb374` | Exported copyout / common consumer | Exact produced-object and constructed-map handoffs |
| `0xfffffe000bde1300` | Map-entry insertion | Original singleton insertion completes |
| `0xfffffe000bddf0b0` | Packed-store vector search | Original newly initialized root search |
| `0xfffffe000bddf2c8` | Packed-store record/key update | Original selected insertion path |
| `0xfffffe000bddf4ec` | Packed-store key/record movement adapter | Original index/count/offset derivation; byte-move leaf modeled |
| `0xfffffe000bddfe6c` | Parent-position maintenance | Original selected root-level path |
| `0xfffffe000be2fac0` | Exclusive entry release | Original selected release after insertion |
| `0xfffffe000bddd5dc` / `...bdc7274` | Real position resolver / candidate adapter | Seven original lookup components, no API models |
| `0xfffffe000c647f10` | Exact `_memcpy` and `_memmove` aliases | Argument-derived overlap-safe byte model |

| Original site | Request/publication |
|---|---|
| `0xfffffe000bdc6eb0` / `...6eb4` | Wrapper supplies page shift 14 / flags 0 |
| `0xfffffe000bdc6f10` | Request map-zone allocation `(zone,aux,0x8004)` |
| `0xfffffe000bdc6f38` | Request distinct root-zone allocation `(zone,aux,0x8004)` |
| `0xfffffe000bdc6f3c` / `...6f44` | Write root sentinel `UINT64_MAX` at+0x10 / header `0x10001` |
| `0xfffffe000bdc6f4c` | Store low32(root_address >> 8) at map+0x48 |
| `0xfffffe000bdc6f50` | Set map+0x88 u32 reference field to 1 |
| `0xfffffe000bdc6f88` | Request map-lock initialization |
| `0xfffffe000bdc6fb8` | Store rounded minimum/maximum |
| `0xfffffe000bdc6fdc` | Store NULL associated pointer in these cases |
| `0xfffffe000bdc7040` / `...7048` | Original LDADD on counter / publish incremented identifier at map+0xc0 |
| `0xfffffe000bddd5bc` / `...5c4` | Optional lower allocation / publish auxiliary store at map+0x90 |
| `0xfffffe000bde16d4` | Call original packed-store update |
| `0xfffffe000bddf538` / `...f5c0` | Request overlapping key bytes / record bytes moves on selected root path |
| `0xfffffe000bdcc1d0` | Release the inserted exclusive entry |
| `0xfffffe000bdcc204` / `...c230` | Request wrapper zeroing / zone release after insertion |

Counter address `0xfffffe000cb810e8` is independently checked against the original ADRP at `...bdc7034` and ADD immediate 0xe8 at `...7038`. The counter's broader native identifier semantics remain unknown. No Mach port or message is emitted at these local object/store sites. Root handles, entry IDs, map pointers, lock identities and output VAs are not Mach names. [MS1,MS4,MS8]

## Construction and source-produced root

The shared machine ABI is `(associated_pointer, minimum:u64, maximum:u64, page_shift:u32, flags:u32)`. The exported wrapper supplies shift 14 and flags 0. All four cases supply NULL associated pointer and explicitly zeroed lower allocation results. Original code initializes some fields directly and leaves others dependent on the allocator's zeroing premise; the complete 256-byte oracle includes both contributions. Native zone identity, zeroing and object extent are not established by these fixtures. [MS2-MS4]

For the tested shifts and non-wrapping bounds:

```text
page_bytes = 1 << page_shift
mask = page_bytes - 1
stored_minimum = (minimum + mask) & ~mask
stored_maximum = maximum & ~mask
```

| Case | Shift / page bytes | Flags / global epoch | Stored bounds relative to private RAM base R | Identifier / counter |
|---|---|---|---|---|
| 0, exported wrapper | 14 /16384 | 0 /0 | R through R+0x100000 | 8 /8 |
| 1, shared constructor | 12 /4096 | 4 /0 | R+0x1000 through R+0xff000 | 0 /7 |
| 2, shared constructor | 14 /16384 | 3 /1 | R+0x4000 through R+0xfc000 | 8 /8 |
| 3, shared constructor | 14 /16384 | 16 /0 | R through R+0x100000 | 8 /8 |

The private counter starts at 7. Flags containing mask 0xc suppress this selected increment/publication path. Flags0/3/16 increment it to 8. Flag16 also reaches original optional auxiliary-store initialization; its lower allocation result is declared. These finite cases establish the selected branches, not all flag or page-shift meanings. No external caller control of the direct probe values is established. [MS3,MS4]

| Field | Original construction / resulting state |
|---|---|
| Map +0x10/+0x18 u64 | Rounded minimum/maximum |
| Map +0x20 u64 / +0x28 u32 | Zero accounting / entry count under stated zeroing premise |
| Map +0x2c/+0x2d u8 | Supplied page shift / value1 |
| Map +0x48 u32 | Encoded root address, `0x30000` in this fixture |
| Map +0x50 u64 | Initially NULL hint; later original insertion publishes root pointer |
| Map +0x58 u64 | NULL associated pointer |
| Map +0x68/+0x70 u64 | `0x7fffffffffffffff` from original vector instructions |
| Map +0x78 u64 | `0x7ffffe000000` |
| Map +0x88 u32 | Reference field1 |
| Map +0x90 u64 | NULL, or declared auxiliary result in flag 16 case |
| Map +0xb0 u32 | Selected flag/global combination; case 2 is `0x01004080` |
| Map +0xc0 u64 | Selected incremented identifier, or zero from allocation premise |
| Root +0x00 u32 | `0x00010001` |
| Root +0x08/+0x10 u64 | Zero / `UINT64_MAX` |
| Other root bytes in256-byte oracle | Zero from allocator premise |

The three canonical auxiliary pages are private CPU backing regions. The new root address `0xfffffe0003000000` is chosen by the allocator model; original instructions construct its bytes and encoded map field. The descriptor decodes as kernel-base prefix plus `(low32 << 8)`. This replaces the former zero-root fixture without attesting that the external map factory is the actual boot producer of native `kernel_map`. The retained global `kernel_map` identity remains a declared component premise. [MS2,MS3,MS5]

## Exact construction-to-copyout chain

The initial source is case4 of the [entry-copy profiles](triage_evidence/kernel_vm_entry_copy_profiles.json), independently reconstructed afresh. Each constructor starts from its complete 1048576-byte RAM snapshot and original auxiliary pages, then adds declared zone/global fixtures. Thirteen later components transfer exact constructor/consumer RAM, all three auxiliary pages and declared globals. Separate call registers are initialized explicitly; native CPU/scheduling continuity is not claimed. [MS2,MS3]

```text
original type2 copy producer -> original map/root constructor
  -> complete RAM/aux/global transfer -> original copyout
       -> lower destination resolver [stop, error model, or success model]
       -> original validation / reuse or clone / relocation
       -> original output store / unlink / exclusive state
       -> original store search / key-record update / map links
       -> original entry release / wrapper cleanup -> return0
            +-> real resolver/candidate lookups
            +-> source-copy or other-descriptor discard -> further lookup
```

The unmodeled lower resolver case still stops at `0xfffffe000bdde9ac`; a declared result3 returns3 and preserves the constructed empty store. Two declared-success cases supply the same destination start used previously. Lower class bounds remain the captured file-zero epoch, so successful range membership/reservation is still a model premise. Original map construction resolves the store-root prerequisite, not the runtime bounds/resolver prerequisite. [MS5,MS7]

For successful structural copyout, logical extent 32769 bytes spans three 16384-byte pages: `ceil(32769/16384) * 16384 = 49152 bytes`. Let D be the declared destination and E=D+49152. The produced root has three records and four boundary keys:

| Root offset | Result |
|---|---|
| +0x00 u32 | `0x00010003` |
| +0x08/+0x10/+0x18/+0x20 u64 | 0 / D / E / `UINT64_MAX` |
| +0xa8 u32 | 0, leading empty interval |
| +0xac u32 | Inserted entry ID: `0x40001` for reuse, `0x40002` for clone |
| +0xb0 u32 | 0, trailing empty interval |

Map head/tail both reference the inserted entry; map+0x20 becomes 49152 and entry count+0x28 becomes 1. The mapped entry retains normalized flags `0x5730`, interval[D,E), NULL associated object and zero singleton links. Original exclusive release changes its word `0x30000 -> 0x10000` and restores thread+0x22c to 0. The selected wrapper is zeroed and passed to its zone-release model; the entry itself remains in the map/store. Output D and raw return0 are checked separately. [MS4,MS6,MS7]

Two byte moves are modeled from original arguments: an 8-byte key move and a 4-byte record move within the root. Original code derives their positions/counts and performs all other store updates. The model reads the source bytes before writing, preserving overlap semantics; independent replay rebuilds those effects from actual registers. Native memcpy execution and hardware concurrency are not tested. [MS6,MS7]

## Ownership continuity and real lookup

Consuming mode reuses the produced entry and retires its48-byte wrapper. Non-consuming mode constructs a distinct 64-byte entry and 48-byte wrapper; after insertion only that temporary wrapper is retired, while the original input copy remains byte-identical. A later original discard zeroes/releases the original entry and wrapper while preserving the mapped clone and complete map/root state. Two subsequent lookups still return the clone. A separate descriptor1 discard preserves the reused mapped entry/store. These are original control/list effects plus modeled zero/free requests, not native allocator retirement or backing-object reference proofs. [MS3,MS6,MS7]

Seven lookup components run original `0xfffffe000bddd5dc` and `0xfffffe000bdc7274` with no API/effect models:

| Source store / query | Boolean result | Output candidate |
|---|---|---|
| Reused entry, D-1 | false | Non-NULL reused entry |
| Reused entry, D | true | Reused entry |
| Reused entry, D+32768 | true | Reused entry |
| Reused entry, E-1 | true | Reused entry |
| Reused entry, E | false | NULL |
| Clone after original input discard, D | true | Distinct mapped clone |
| Clone after original input discard, E | false | NULL |

The before-start false result can retain a non-NULL candidate. The complete Boolean must be checked. The E-1 hit concerns the rounded map interval, not proof of additional logical payload bytes. The earlier [fixed-position candidate tests](kernel_vm_range_cursor_report.md) isolated the adapter's local start predicate and could return true at end under that supplied position; the current original resolver correctly selects the trailing empty record at E in this constructed singleton store. These results are compatible and have different premises. No arbitrary-map or native access-right claim follows. [MS4-MS6,MS8]

## Environmental reference inventory

A fresh syntactic scan covers 2558560 instruction words in kernel code sections and finds 116 ADRP references to page `0xfffffe0007e69000`. Each 96-byte window, containing-function identity and raw instruction sequence is recaptured and independently verified. The page includes class bounds at `...7e69f90`; same-page references also address other data. Readers, classifiers and diagnostic pointer publications do not by themselves establish initialization writers. Indirect pointers, other address constructions, transitive aliases and writes outside these windows are not exhaustively resolved. The class-bounds initialization producer and live values remain unknown. [MS1,MS5,MS8]

## Assumption register

| ID | Assumption / dependent claims | Stress test or falsification probe |
|---|---|---|
| MS1 | Pinned collection functions, original aliases/constants and reference windows describe this build | Recapture all 69 functions, primitive symbols, counter ADRP+ADD and 116 windows; verify runtime build pairing separately |
| MS2 | Normalized reply and original produced copy are relevant component inputs; generic map factory output is a structural destination premise | Reconstruct source producer; establish actual boot kernel-map and authentic FairPlay caller/namespace/reply before full exchange claims |
| MS3 | Exact snapshots, private regions, zone/global epochs and separate call registers define stable components | Compare full RAM/pages/globals; replace declared identities and test aliasing/concurrency separately |
| MS4 | NULL associated objects, shifts 12/14, stated non-wrapping bounds and finite flag/query cases bound the semantics | Cover non-NULL/tagged objects, other shifts/flags, multi-entry stores and actual input producers |
| MS5 | File-zero class bounds and declared kernel-map identity are not native runtime state | Recover boot/runtime writers, real class bounds and lower resolver; reject native reservation claims based on modeled success |
| MS6 | Exact store/map/node oracles, instruction order and real lookup compose the selected structural lifetime | Check all bytes, clone/source disjointness and release joins; extend removal, split/rebalance, references and payload paths |
| MS7 | Zeroed allocation, locks, resolver, memmove, zero/free and logical PAC provide only declared outcomes | Independently rebuild effects and raw ABIs; replace each premise before native mappings, rights, retirement or hardware-authentication claims |
| MS8 | Seventeen cases and syntactic ADRP inventory do not exhaust all interfaces | Continue real resolver/bounds, non-NULL backing bytes, larger stores, native map provenance and authentic daemon/kext transport |

## Verification and bounded continuation

Seventeen independent CPU replays check 3043 original instruction visits, 839 reads /6015 bytes, 683 writes /5134 bytes and all 17 final boundaries. They compare 17 complete primary images /17825792 bytes, 51 auxiliary-region records and 204 global records. Forty-three API models and 20 argument-derived effect patches /2408 bytes pass. Four complete 256-byte map/root oracle pairs, two completed copyouts, seven real-resolver lookups and exact component handoffs are verified. Sixteen components return; one explicitly stops before the lower range resolver.

```text
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_map_store_init.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_map_store_init.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_map_store_init.py
```

Recovery/validation is O(image + instruction words + captured bytes + visits + RAM + effects) time and O(image + source + RAM + journals + reference windows) space. Primary RAM is 1048576 bytes per case; each auxiliary page is 4096 bytes. Stored compressed snapshots add artifact storage. Page arithmetic and byte counts above are exact for these fixtures; no native-performance or statistical claim is made.

| Impact | Bounded continuation | Additional evidence |
|---|---|---|
| High | Recover actual boot kernel-map and class-bounds initialization | Replace generic destination identity and file-zero environment premises |
| High | Execute real lower range resolver with established runtime inputs | Replace destination-reservation/membership model |
| High | Recover non-NULL backing-object copy and authentic FairPlay reply | Establish actual data provenance beyond structural NULL entries |
| High | Join kext caller, daemon namespace/transport and returned copy state | Cross-layer continuity beyond separate CPU components |
| Medium | Map removal, multi-entry insertion, split/rebalance and non-NULL associated objects | Extend store and ownership semantics beyond singleton cases |

QG1: Factual technical analysis; no normative judgment required.
QG2: MS1-MS8 identify premises, dependent conclusions and falsification probes.
QG3: Scoped routine identities/roles, original call/store sites, constructor/store/copyout/lookup ABI, data/control/lifetime/environment and respective reporting updates are covered. Full goal remains incomplete.
QG4: Explicit widths, offsets, encodings, byte/page calculations, exact snapshot sizes, costs and commands are reproducible.
QG5: Allocator zeroing versus original writes, generic map versus boot kernel-map, class-bound models versus real store execution, candidate versus Boolean result, rounded interval versus payload and modeled versus native retirement are distinguished.
QG6: Original hashes/symbols/functions/constants, independently repeated scan, source-producer reconstruction, byte/field oracles and fresh CPU/effect replay provide primary provenance.
QG7: Impact-labelled continuation remains bounded to unresolved VM, backing-object and FairPlay interfaces.

[Preservation](triage_evidence/kernel_map_store_init_delivery.json), [scoped gates](triage_evidence/kernel_map_store_init_quality_gates.json), [publication verifier](triage_evidence/verify_kernel_map_store_init_publication.py). The full goal remains active.
