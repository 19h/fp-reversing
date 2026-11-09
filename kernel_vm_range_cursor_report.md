# VM range cursor, encoded entry candidates and type-2 factory frontier

Original type-2 construction now passes its former range-lookup boundary. An empty declared store reaches original failure cleanup and returns `0x1000000c`; a populated declared store reaches original entry-copy body `0xfffffe000bdd21fc` with a selected entry and held reader state. Successful type-2 copy construction/publication remains unknown. The shared initializer, candidate decoder and original factory callback are independently checked. Native mapping membership, rights, map-store allocation and complete FairPlay transport are not established.

Evidence: [source/functions/fixup](triage_evidence/kernel_vm_range_cursor_source.json), [38 private CPU cases](triage_evidence/kernel_vm_range_cursor_profiles.json), [fresh replay and field/guard oracles](triage_evidence/kernel_vm_range_cursor_checks.json). Original collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. The source set contains 41 retained/new complete functions / 7474 instructions. Original files suffice; no IDA query/mutation, native target, IPC, VM operation or saved-memory update occurred.

## Functions and newly joined control flow

| Address | Original identity / inferred role | Coverage |
|---|---|---|
| `0xfffffe000be31808` | Anonymous range-cursor initializer | Complete 56-instruction body and 17 standalone cases |
| `0xfffffe000be318e8` | Anonymous read-oriented range acquisition/walk | Original factory call, selected empty/populated paths |
| `0xfffffe000be3218c` | Anonymous alternate range validation/walk | Complete source captured; factory call context and common initializer ABI recovered; body not dynamically exercised here |
| `0xfffffe000bdc7274` | Anonymous packed-store candidate decoder/lookup adapter | Original decoder executes using declared position results |
| `0xfffffe000bddd5dc` | Anonymous lower store-position resolver | Captured; its output is a model, not a recovered complete search |
| `0xfffffe000be32a0c` | Anonymous cursor callback dispatcher | Original factory callback-object load and call |
| `0xfffffe000bdd2750` | Anonymous entry/object/global/page-shift filter | All selected branches in 14 standalone cases, plus real factory callback join |
| `0xfffffe000be33a44` | Anonymous range iterator | Original selected populated-entry return |
| `0xfffffe000be2fdb8` | Anonymous entry reader-acquire path | Original uncontended atomic/counter path executes |
| `0xfffffe000bdd20d8` / `...bdc6608` | Anonymous entry eligibility/policy chain | Original selected factory path executes |
| `0xfffffe000bdd21fc` | Anonymous entry-copy/processing helper | Complete body captured; execution stops at entry |

These names describe inferred roles, not exact nlist identities. In particular, the two larger frontiers are range processors rather than established simple tree-lookup functions. [VR1,VR8]

```text
original outgoing reply body -> original VM-copy factory, extent32769
  -> working type2 header -> read-lock call [model]
  -> original cursor initializer -> range walk
       -> store-position result [model] -> original packed candidate decoder
       +-> empty -> range result1 -> working-header discard/cleanup -> body error
       +-> entry -> original reader acquire -> original bound callback
                   -> range result0 -> iterator returns entry
                   -> eligibility chain -> entry-copy body [stop]
```

The input body is the exact retained normalized reply seed from [copyin case 42](triage_evidence/rpc502_reply_copyin_profiles.json), with explicit extent substitutions. G=2/V=0 and declared map/thread prerequisites are retained from the [VM handoff work](rpc502_vm_handoff_report.md). Native reply extents and actual map-store provenance remain unknown. [VR2-VR4]

## Cursor initialization and publication

Machine arguments are `(cursor, map, start:u64, end:u64, flags:u32)`. Original code writes the cursor before range validation. On success it stores the cursor at thread+0x238 and returns0; on range rejection it returns1 and preserves that thread field. Seventeen cases yield 11 successes and six rejections. Failed initialization therefore does not imply an untouched cursor. [VR3,VR5]

| Cursor byte offset | Original initialization |
|---|---|
| +0x00 / +0x08 | Requested start / end, each u64 |
| +0x10 / +0x18 | Map pointer / NULL current entry |
| +0x20 | Caller-supplied u64 preserved |
| +0x28 | u32 flags, with conditional bit31 adjustment |
| +0x2c | u16 mode value3 |
| +0x2e through +0x47 | Zeroed by original unaligned stores; +0x30 becomes start if flag bit2 is set |
| +0x48 / +0x50 / +0x58 | Saved initial start / end / map |
| +0x60 / +0x68 | Zero u64 values |
| +0x70 onward | Untouched in the 128-byte observation window |

The touched region reaches byte+0x6f, or 112 bytes. This establishes a touched extent and caller preservation, not a complete private-type allocation size. The original factory preloads caller word+0x20 with `0xfffffe0007e6a140`; both type-2 cases preserve it through initialization. [VR3,VR5]

Original local bounds rules, using unsigned 64-bit comparisons:

```text
if flags bit12:
    input start=end=0 is required by the source assertion
    effective start=0; effective end=u64(-1) << map.page_shift
if flags & 0x3000:
    require effective start < effective end
else:
    require map.minimum <= start < end <= map.maximum
```

Only the valid zero/zero inputs exercise bit12; the assertion path is not executed. Page shifts12 and14 produce exact u64 masks with 12 or14 low zero bits. Flag words `0x40019` and `0x42015` come from the two original factory call contexts. Their bounds behavior differs because bit13 changes the tested mask; the broader meanings/authorization of those flags are not established. No actual VM access is attempted by these initializer cases. [VR3,VR5]

A non-NULL associated pointer at map+0x58 is logically authenticated with field-address modifier incorporating `0x250c`. Equality to original literal address `0xfffffe000cb0bf18` adds flag bit31; NULL and another declared pointer do not. That literal has no exact nlist identity in this artifact. Hardware authentication and the native associated-object type remain unknown. [VR1,VR3]

## Encoded candidate interface

Five cases execute the original adapter using a declared lower position `0x20000`. Its low32 bits select a 256-byte-scaled page position; upper bits select a four-byte slot. The supplied slot contains a 31-bit record ID, decoded on the exercised direct path as `0xfffffe0000000000 + (ID << 6)`. Private auxiliary regions hold the declared page/entry bytes; they are separate from original collection pages and do not represent native allocated objects. Other tagged/multi-page decoder paths remain unexecuted. [VR4]

For this fixed supplied position, a nonzero decoded candidate is written to the output and the local Boolean is `candidate.start <= query`. Four queries cover just before start, start, end-1 and end. The before-start case returns false with a non-NULL output; the end case returns true under the same supplied candidate position. An empty slot returns false/NULL. These are local decoder results. Correct native address membership depends on the unexecuted position resolver's contract; no native bounds bypass or mapping rights follow from this fixture. [VR4,VR8]

## Exact callback binding and local filter

The factory's preserved caller word points to an original callback object. Dispatcher `0xfffffe000be32a0c` loads its slot+0x10 and calls through `BLRAA` at `0xfffffe000be32a5c`.

| Binding field | Original value |
|---|---|
| Callback object | `0xfffffe0007e6a140` |
| Slot | `0xfffffe0007e6a150` |
| Decoded target | `0xfffffe000bdd2750` |
| Raw chained word | `0x8011000004dce750` |
| Format / authentication / diversity / address diversity / key | 8 / 1 / 0 / 1 / 0 |
| Observed call arguments | `(callback_object, cursor, entry)` |
| Observed modifier | Exact slot address |

The slot and target are freshly recaptured. Execution follows only that exact binding; the authentication operation remains logical. This is an original factory-selected callback, not evidence of external caller control over its target. [VR1,VR6]

The 26-instruction callback reads the associated object selected from entry+0x28. For aligned non-NULL objects, it uses the u32 word at object+0x68. The selected cases return raw `0x20008002` exactly when all conditions hold: non-NULL object, word value4, entry byte+0x38 bit3 clear, and absence of the special global/map/page-shift condition. That special condition is nonzero u32 at `0xfffffe000cae4e58`, non-NULL cursor map and map page shift below14. Other selected cases return0. The tagged-object fallback and complete object layout remain unknown. [VR3,VR6]

Fourteen standalone cases cover object word3/4, NULL object, global0/1, NULL map and page shifts12/14, and the entry bit. Five return the private status and nine return0. There are no source memory writes in these callback components. A zero local filter result is not a native permission or policy-success proof. Original-file global bytes are retained separately from the supplied values. [VR6]

## Type-2 empty failure and held populated frontier

The logical copy extent32769 bytes starts at a 16384-byte-aligned source VA. The selected range covers `ceil(32769/16384) * 16384 = 49152 bytes`, while the working copy header retains the exact logical u64 extent32769. Range coverage and payload extent are distinct. [VR2-VR5]

| Case | Original observed progression | Unestablished continuation |
|---|---|---|
| Empty declared store | Range returns1; no iterator entry; original working-header discard; body returns `0x1000000c`; descriptor remains source VA; active-cursor field cleared | Native allocation/free, real store state and full send result |
| Populated declared store | Range returns0; exact callback runs; iterator returns entry; cursor mode3 becomes1; eligibility chain reaches entry-copy body | Entry copying, list construction, final copy publication and success |

In the populated case, original entry acquisition changes the supplied lock word `0x10000 -> 0x50000` using an addition of `0x40000`, and thread word+0x22c changes0->1. At the recorded entry-copy boundary that state is still held, current cursor points at the entry, and thread+0x238 points at the cursor. Map read-lock/unlock calls remain no-effect models. The boundary is inside the protocol; no leak, native reference balance or eventual release is established. [VR4-VR7]

The source entry-copy arguments are `(cursor, selected_entry, options=1, out_entry_pointer)`. The working type-2 header is not yet published into the descriptor. The empty case requests header zeroing/release with no source-removal request and no successful copy publication. Lower allocation, zeroing/free and message cleanup remain models. [VR2,VR7]

## Assumption register

| ID | Assumption / dependent claims | Stress test or falsification probe |
|---|---|---|
| VR1 | Hash-pinned source and original fixups describe the intended build | Recapture all41 functions and callback slot; verify actual runtime image pairing separately |
| VR2 | Retained normalized reply and extent substitution describe this private factory entry | Compare seed provenance; join authentic header/namespace/transport before a complete FairPlay claim |
| VR3 | Map, page-shift, associated pointer and global fixtures are the stated epochs | Check exact fields/branches; recover native writers and actual state before environmental attribution |
| VR4 | Supplied position, auxiliary page/entry bytes and uncontended entry state describe only the selected structural path | Execute the real resolver/allocator and native lifetime contracts before membership/provenance claims |
| VR5 | The captured cursor window and thread slot remain disjoint and stable | Verify exact128 bytes and out-of-touched preservation; examine aliases/concurrency and further callers separately |
| VR6 | Original callback binding and raw object/global/bit fields describe the local filter | Recapture slot metadata, all selected branches and actual native object types; hardware PAC remains untested |
| VR7 | Lower allocation/lock/zeroing/free outcomes allow the original prefix/cleanup | Rebuild effect records; continue from the held frontier before ownership-completion claims |
| VR8 | The direct candidate branch, 38 cases and entry-copy stop define the evidence scope | Cover resolver/tagged/submap/retry/entry-copy continuations; keep broader goal active until full interfaces are established |

## Verification and bounded continuation

Thirty-eight independent CPU replays check 1966 original instruction visits, 344 reads / 2248 bytes, 596 writes / 4323 bytes and all final boundaries. They compare 38 complete private RAM images / 39845888 bytes, 42 auxiliary-region records and 280 declared global records. Sixteen API models, one exact logical callback edge, 15 callback-entry frames and three factory return frames are checked. No native mapping, rights, hardware PAC or VM operation executes.

```text
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_vm_range_cursor.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_vm_range_cursor.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_vm_range_cursor.py
```

Recovery is O(image + captured bytes) time/space. Replay is O(visits + RAM + effects) time and O(image + RAM + journals) working space; retained snapshots add compressed artifact storage. Each primary RAM image is1048576 bytes; auxiliary pages are4096 bytes each when present. All arithmetic above is exact in the tested domain.

| Impact | Bounded continuation | Evidence it would add |
|---|---|---|
| High | Resume original entry-copy body with the saved held state | Establish entry creation, list linkage, publication and release completion |
| High | Recover actual store-position resolution and native entry allocation | Replace the position/geometry premises before mapping-membership claims |
| High | Join authentic FairPlay caller, namespace and transport | Replace normalized seed/component assumptions |
| Medium | Tagged objects, submaps, retries and alternate range routine | Extend cursor/filter/lock semantics beyond the selected direct path |
| Medium | Native callback global and object-field writers | Refine environmental and policy attribution |

QG1: Factual technical analysis; no normative judgment required.
QG2: VR1-VR8 enumerate assumptions, dependencies and falsification probes.
QG3: Scoped anonymous roles, cursor/callback/decoder ABI, type2 failure/frontier, environment and respective report updates are covered; broad completion remains false.
QG4: u32/u64 fields, byte offsets, masks, pages, extents, exact snapshot sizes, costs and commands are explicit.
QG5: Cursor writes before rejection, preserved caller word, local candidate versus native membership, model/real callback, and held versus completed lifetime are distinguished. Remaining paths are explicitly unknown.
QG6: Original hashes/functions/fixup, exact frame/state journals, independent source/effect replay and finite oracles provide primary provenance.
QG7: Impact-labelled continuation remains bounded to unresolved VM and FairPlay interfaces.

[Preservation](triage_evidence/kernel_vm_range_cursor_delivery.json), [scoped gates](triage_evidence/kernel_vm_range_cursor_quality_gates.json), [publication verifier](triage_evidence/verify_kernel_vm_range_cursor_publication.py). The full goal remains active.
