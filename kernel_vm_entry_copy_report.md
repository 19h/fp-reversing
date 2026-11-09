# VM entry eligibility, type-2 copy construction and discard

Original code now completes the former entry-copy frontier under an explicit NULL-associated-object fixture. The exact saved state rejects its original flags; a separately declared eligible entry produces a one-entry type-2 copy, publishes both descriptor pointers and later executes original unlink/discard. This establishes structural VM-copy behavior, not authentic FairPlay payload bytes, native VM removal, allocator retirement or a complete daemon/kext exchange. [EC1-EC8]

Evidence: [50 complete functions / 8224 instructions](triage_evidence/kernel_vm_entry_copy_source.json), [seven private CPU cases](triage_evidence/kernel_vm_entry_copy_profiles.json), [independent replay and field oracles](triage_evidence/kernel_vm_entry_copy_checks.json). Collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Original files suffice; no new IDA access, IDB mutation, saved-memory update, native target execution or native IPC occurs.

## Original routines and emission sites

Names below are inferred roles, not established original symbol identities. A requested operation at a machine call site is distinguished from its modeled result.

| Address | Inferred function / selected evidence |
|---|---|
| `0xfffffe000bdd21fc` | Entry eligibility and 64-byte clone/adjustment; five entry/return frames |
| `0xfffffe000bdc6728` | Entry flag adjustment; selected clone path executes |
| `0xfffffe000bdee258` | Associated-object copy helper; original NULL-object branch executes |
| `0xfffffe000bde11e0` | Copy-list append; original count/head/tail stores execute |
| `0xfffffe000be3431c` | Cursor release; original entry-reader and thread bookkeeping unwind |
| `0xfffffe000bdd014c` | Lower source-range removal; body captured, call result modeled |
| `0xfffffe000bde1248` | Copy-list unlink; selected original type-2 discard executes |
| `0xfffffe000be304e8` | Entry preparation for release; selected NULL-object path executes |
| `0xfffffe000bdc6308` | Copy discard; original type-2 and type-3 control paths execute |

| Site | Original request or store | Evidence boundary |
|---|---|---|
| `0xfffffe000bdd22b4` | Call raw zone allocator `0xfffffe000bd75c64` with `(entry_zone, auxiliary, 0x8004)` | New-entry address supplied by model |
| `0xfffffe000bdd22bc` through `...22d0` | Original vector instructions copy 64 entry bytes | Private source/destination bytes independently replayed |
| `0xfffffe000bdd2464` | Call associated-object helper with NULL object in this fixture | No real mapped-object payload established |
| `0xfffffe000bdd1804` | Call copy-list append | Original linkage/count writes |
| `0xfffffe000bde1228` / `...122c` | Increment count / store list head and tail | One-entry type-2 header |
| `0xfffffe000bdd1b3c` | Request source removal via `0xfffffe000bdd014c` | `(map,start,end,0,0)`, declared zero result and no map mutation |
| `0xfffffe000bdd1f38` | Publish produced copy to factory output | Follows the source-removal request |
| `0xfffffe000bcc4a30` through `...4a44` | Descriptor pointer sign/store sequence | Logical PAC; native authentication untested |
| `0xfffffe000bdc643c` / `...6444` | Unlink entry / prepare entry for release | Original instructions |
| `0xfffffe000bdc6414` / `...6428` | Request zeroing / zone release of 64-byte entry | Explicit zero/free models |

These are local kernel object interfaces. They emit no new Mach message, create no established Mach right and identify no new receive/send port. Earlier daemon registrations and RPC502/700 destinations remain separate evidence. The historical zut trace still ends at failed UserClient open; these components do not extend that trace. [EC2,EC7,EC8]

```text
saved held entry-copy state -> original eligibility -> rejection -> unwind/error

separate eligible fixture -> original 64-byte clone/adjustment
  -> NULL-object helper -> original list append -> reader/cursor unwind
  -> source-removal request [model] -> original type2 publication
  -> original descriptor0 store -> separate type3 descriptor1 construction
  -> exact RAM/aux/global transfer -> original type2 unlink/discard
  -> exact RAM/aux/global transfer -> original type3 discard
```

## Saved state and eligibility

The prior [held frontier](kernel_vm_range_cursor_report.md) is reconstructed afresh before resumption. Replay compares all 31 general registers, SP, NZCV, 32 vector registers, the complete 1048576-byte primary RAM image, auxiliary pages and declared image globals. Original saved flags remain `0x100`; they are not changed in the resumed case. [EC3]

For NULL associated object and options=1, the exercised gate requires source-entry flags bit8 and bit4. The broader source also permits options bit1 as an alternative to bit4; that option is not exercised here. Four independent factory cases vary only the declared entry flags. These finite cases are not an exhaustive flag-space proof. [EC4]

| Case | Mode | Entry flags | Entry helper X0 | Reply-body X0 | Source instruction visits |
|---|---|---|---|---|---|
| 0 | Exact saved-state resume | `0x100` | 2 | `0x1000000c` | 189 |
| 1 | Factory | `0x0` | 2 | `0x1000000c` | 787 |
| 2 | Factory | `0x10` | 2 | `0x1000000c` | 787 |
| 3 | Factory | `0x100` | 2 | `0x1000000c` | 795 |
| 4 | Factory | `0x110` | 0 | 0 | 1220 |
| 5 | Discard produced descriptor0 | Produced type2 | Not entered | Discard X0=0 | 151 |
| 6 | Discard produced descriptor1 | Produced type3 | Not entered | Discard X0=0 | 69 |

All seven components return. Original unwind restores the source entry reader word from `0x50000` to `0x10000`, thread+0x22c to zero and active cursor thread+0x238 to NULL. Rejection allocates no cloned entry, zeroes/releases the working 48-byte copy header and leaves descriptor0 holding its source VA. Map lock calls remain models; these local bookkeeping results do not establish native lock/reference balance. [EC3,EC5,EC7]

## Produced entry and header

The successful case uses page shift14: page size `2^14 = 16384 bytes`. Logical extent32769 bytes covers `ceil(32769/16384) * 16384 = 49152 bytes`. Original copy construction retains the logical extent separately from the entry interval. [EC4,EC6]

| Object / byte offset | Source-produced value |
|---|---|
| New entry +0x00 u64 | 1, from original constant at `0xfffffe000700dc38` |
| New entry +0x04 u32 / +0x08 u64 | Zero previous/next encoding for singleton |
| New entry +0x10 / +0x18 u64 | Start / end, interval width49152 bytes |
| New entry +0x20 through +0x37 | Zero in selected NULL-object fixture |
| New entry +0x38 u32 | `0x4110`, after original adjustment |
| New entry +0x3c u32 | Zero |
| Copy header +0x00 / +0x08 u64 | Same new-entry head/tail pointer |
| Copy header +0x10 u64 | Original source start |
| Copy header +0x18 u64 | Zero |
| Copy header +0x20 u64 | Logical extent32769 bytes |
| Copy header +0x28 u32 | Entry count1 |
| Copy header +0x2c / +0x2d u8 | Page shift14 / type2 |

The initializer value1 in the cloned entry differs from the restored source entry reader word `0x10000`. They are different object states; neither value is inferred from the other. The original entry-zone file cells are recaptured separately from the declared private zone/auxiliary pointers. Their native runtime identity remains unknown. [EC1,EC5]

Both descriptor pointer stores are checked in the 392-byte message snapshot. Descriptor0 references the original-code-produced type2 wrapper; descriptor1 references a separately produced type3 copy of extent1. The NULL associated object means the type2 entry carries no established backing VM object or actual FairPlay bytes. Structural publication is the confirmed result. [EC2,EC4,EC6]

## Discard continuity and external effects

Case5 starts from case4's exact complete primary RAM, auxiliary pages and declared globals; case6 starts from case5's resulting state. Registers are initialized for separate discard calls. These transfers establish component data continuity, not native scheduling or uninterrupted CPU execution. [EC6]

Original type2 discard unlinks the new entry and requests 64-byte zeroing/release before requesting 48-byte wrapper zeroing/release. The second produced copy remains intact through that component. The next component requests type3 backing/wrapper cleanup. Independent replay derives each modeled effect from call arguments and checks original load/store journals around it. No native allocator retirement occurs. Descriptor pointer bits remain after the pointed-to private storage is zeroed; these stale values do not establish retained ownership or an error in an unexecuted caller. [EC6,EC7]

## Assumption register

| ID | Assumption / dependent claims | Stress test or falsification probe |
|---|---|---|
| EC1 | Pinned collection functions, constants and authenticated callback slot describe this build | Recapture all50 functions, raw bytes, constant and slot; verify actual runtime build pairing separately |
| EC2 | Retained normalized reply seed and substituted extents define this private entry | Match seed provenance; join authentic FairPlay caller, header, namespace and transport before full exchange claims |
| EC3 | Saved GP/SP/NZCV/SIMD/RAM/aux/global state represents the prior held boundary | Independently reconstruct the prefix and compare exact transfers; test aliases and concurrent mutation separately |
| EC4 | NULL object, options1, map/thread/global and bit fixtures define the tested epochs | Inspect exact bit branches; cover options bit1, non-NULL/tagged objects, submaps and actual field writers |
| EC5 | Private zone/auxiliary addresses and uncontended entry state permit selected construction/unwind | Verify allocator ABI and original initializer constant; recover real allocation, identity and lifetime contracts |
| EC6 | Full-memory component transfers preserve produced structures | Compare every primary byte, auxiliary page, global and descriptor; authentic CPU/transport continuity remains untested |
| EC7 | Position, lock, allocation, source-removal, zero/free and logical PAC models supply declared outcomes | Independently derive argument/effect records; replace each model before native membership, rights or retirement claims |
| EC8 | Seven cases and selected NULL-object branches bound the result | Extend non-NULL object copying, type2 copyout, real resolver and genuine transport; full goal remains active |

## Reproduction, verification and bounded continuation

Seven fresh CPU replays check3998 original instruction visits, 1057 reads /7342 bytes and1031 writes /7644 bytes. They compare seven complete primary images /7340032 bytes,14 auxiliary-region records and55 image-global records. Forty-five API models,11 entry-copy frames, five helper-return frames, eight effect patches /353 bytes and all seven final boundaries pass. Captured source contains50 complete functions /8224 instructions. Counts describe this increment only.

```text
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_vm_entry_copy.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_vm_entry_copy.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_vm_entry_copy.py
```

Recovery is O(image + captured bytes) time/space. Replay is O(visits + RAM + effects) time and O(image + RAM + journals) space; stored compressed snapshots add artifact storage. Primary RAM is1048576 bytes per case; each auxiliary page is4096 bytes. Arithmetic is exact within these fixtures, with no statistical or native-performance claim.

| Impact | Bounded next step | Additional evidence |
|---|---|---|
| High | Recover non-NULL associated-object copying and its real input producer | Backing-object identity, byte provenance and ownership beyond structural NULL fixture |
| High | Transfer produced type2 object into original copyout | Consumer contract and entry-list traversal under stated models |
| High | Replace lower store-position and source-removal premises | Actual mapping membership and source-map effects |
| High | Join authentic FairPlay request, namespace and daemon reply | Cross-component continuity beyond normalized seed and historical failed-open trace |
| Medium | Exercise options bit1, tagged/submap/retry paths and allocator errors | Scope of eligibility, unwind and alternate ownership paths |

QG1: Factual technical analysis; no normative judgment required.
QG2: EC1-EC8 identify premises, dependent claims and falsification probes.
QG3: Scoped routine roles, local call/store emission sites, entry/copy ABI, data/control/environment and respective reporting updates are covered. Full goal remains incomplete.
QG4: Explicit u8/u32/u64 widths, byte offsets/extents, page arithmetic, snapshot sizes, costs and commands are reproducible.
QG5: Exact resume versus changed factory fixture, source versus cloned lock words, logical extent versus interval, structural copy versus payload, and stale pointer bits versus ownership are distinguished. Unexecuted paths remain unknown.
QG6: Original source/constant/fixup recapture, exact state journals, independent CPU/effect replay and field oracles provide primary provenance.
QG7: Impact-labelled continuation is bounded to unresolved VM and FairPlay interfaces.

[Preservation](triage_evidence/kernel_vm_entry_copy_delivery.json), [scoped gates](triage_evidence/kernel_vm_entry_copy_quality_gates.json), [publication verifier](triage_evidence/verify_kernel_vm_entry_copy_publication.py). The full goal remains active.
