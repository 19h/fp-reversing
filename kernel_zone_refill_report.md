# Original IPC magazine refill and partial-page allocation

The original refill path now runs from the exact held CPU/RAM state previously stopped at refill, through shared/local magazine handling or original partial-page/bitmap allocation, back into the original kmsg constructor. Ten components return constructed inline messages; two empty/gated components reach the deeper zone fallback with nesting still held. No whole refill, fill, bitmap-selection, allocation or zero-check return model is used. Inventory, raw page arena, metadata, control globals and lock acquisition remain explicit premises; native page creation, concurrency, authentication and total FairPlay transport remain unknown. [ZR1-ZR8]

Evidence: [19 complete functions / 3511 instructions](triage_evidence/kernel_zone_refill_source.json), [12 held-state continuations](triage_evidence/kernel_zone_refill_profiles.json), [fresh producer/replay and independent state oracles](triage_evidence/kernel_zone_refill_checks.json), [delivery seal](triage_evidence/kernel_zone_refill_delivery.json), [quality gates](triage_evidence/kernel_zone_refill_quality_gates.json). Original kernel collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Local reference bytes suffice; no IDA query, IDB/memory-store mutation, native target launch, allocation or IPC occurs.

## Newly established original routines and interfaces

| Entry/site | Established role | Evidence limit |
|---|---|---|
| `0xfffffe000bd75e20` | Refill current cache from local/shared full-magazine inventory; spill selected empties; call deeper fill if no magazine supplies entries | Complete 349-instruction body; selected NULL-callback paths executed |
| `0xfffffe000bd76db4` | Fill current slot array from available partial-page elements, update bitmap/page/list/accounting and cache count | Complete 320-instruction body; selected external one-word bitmap paths executed |
| `0xfffffe000bd76ad0` | Select a free element index after a per-CPU cursor, wrapping as needed; remove its bitmap bit and update cursor | Complete 110-instruction body; 33 selected calls and returns verified |
| `0xfffffe000bd75de0` | Original fast allocator calls refill with `(zone,0,flags,selected_cache)` | Actual held call state imported without GP/SP/NZCV/SIMD overrides |
| `0xfffffe000bd76290` | Refill calls deeper fill with `(zone,flags,selected_cache)` | Original call/return verified in three populated-page cases and both fallback cases |
| `0xfffffe000bd76f6c` | Fill calls selector with `(zone,selected_statistics,page_metadata,flags)` | Actual selected index feeds original element-address store |
| `0xfffffe000bd76394` | Deeper zone-allocation fallback after refill supplies no current entries | Previously captured 401-instruction body; stopped before its execution here |
| `0xfffffe000bd0ae78` | Requested lock-acquisition helper, with cache or zone-lock address | Call ABI/model clobbers checked; actual lock effect unexecuted |

Exact original symbols for the three new routines are absent. These role names describe observed source behavior. The complete bodies also contain unexecuted authenticated callback, contention, inline-bitmap and multiword paths; capture does not imply all-path execution. [ZR1,ZR4,ZR8]

## Exact producer-to-consumer continuation

The producer is case 7 of the [startup/zone report](kernel_zone_startup_report.md): the original constructor has already entered the source-created fixed ID-24 zone, incremented thread nesting to 1 and called refill with no current/spare entries. This increment imports all 31 GP registers, SP, NZCV, all 32 SIMD registers, the complete 1048576-byte private RAM and every recorded image-global region. The current thread system register is retained at its declared value. A fresh independent replay verifies that producer prefix before the new continuations. [ZR2]

```text
source-created ID24 zone
  -> original constructor -> original fast zone allocation
       nesting 0 -> 1; current/spare empty
       |
       +-- exact held refill PC/GP/SP/NZCV/SIMD/RAM/globals
             |
             +-> local full magazine, when available
             +-> shared full magazine, directly or through local inventory
             +-> original partial-page fill -> original free-bit selection
             |
             +-> original current pop -> nesting 1 -> 0
             |    -> original 256-byte zero check -> original constructor return
             |
             +-> no entries -> original fallback entry, nesting remains 1
```

Inventory/page/control-state overlays occur after this exact transfer. Every overlay retains its before/after bytes and reason; an independent input-plan check admits only the stated fields and raw storage. There is no new constructor call epoch and no direct current-count/current-slot fill fixture in these continuations. The original refill/fill code creates the usable current state. Native admissibility of the supplied inventory and page epochs is unknown. [ZR2-ZR4]

## Magazine inventory layout and control flow

| Object/offset | Recovered role on selected paths |
|---|---|
| Cache `+0x04` / `+0x06`, u16 | Current/spare element counts |
| Cache `+0x08` / `+0x10` | Current/spare slot-array pointers; magazine header is 16 bytes before slot array |
| Cache `+0x18` / `+0x1c`, u32 | Local full/empty magazine counts |
| Cache `+0x20` | Head of concatenated local full-prefix/empty-suffix list |
| Cache `+0x28` | Address of the link after the last local full magazine; head-cell address when full count is zero |
| Zone `+0x48` / `+0x4c`, u32 | Shared full/empty magazine counts |
| Zone `+0x50` | Shared full-prefix/empty-suffix list head |
| Zone `+0x58` | Address of the link after the last shared full magazine; head-cell address when full count is zero |
| Zone `+0x60` | Shared-depot lock word; original selected acquire/release instructions execute |
| Zone `+0x7c`, u16 | Active local magazine quota read by refill |
| Zone `+0x7e`, u16 | Separate numeric cache bound computed by startup; not the active quota field |

```text
zone +0x50 -> full0 -> full1 -> empty0 -> empty1 -> NULL
                      |
zone +0x58 -----------+  address of full1's next-link cell

No full prefix: zone +0x58 = address of zone +0x50.
The cache uses the same partition convention at +0x20/+0x28.
```

The boundary fields are not unconditional list-tail pointers. Original exchanges remove a full magazine, clear its 16-byte header, install its slot array and move the previous current magazine into empty inventory. Shared and local counts, partition boundaries and all 19 checked next links match independent list-state oracles. Spare inventory remains unchanged in these selected continuations. [ZR3,ZR5]

The source-created kmsg zone has active quota 0 and the earlier startup-computed bound 256. Positive quota 2 is a controlled variant, not an observed runtime setting. With quota 0, refill consumes a shared full magazine directly. With positive quota and an already nonempty local full list, it immediately consumes that local magazine, bypassing shared locking and empty spill. An empty count above the quota therefore does not imply an immediate spill. [ZR3,ZR5]

When the local full list is exhausted and refill enters shared handling, the tested quota-2 case with four local empty magazines retains one, spills three to shared empty inventory, and takes one of two shared full magazines. The transfer bound is reduced by the retained empty count. After replacing current, local empty count is 2; shared full/empty counts are 1/3. A separate security-bit-12 variant executes the alternate local-list insertion branch under otherwise identical empty-local-full inputs; its final list state is equal in that selected case. Native settings and non-NULL callback behavior remain unknown. [ZR3,ZR5]

The original shared-lock sequence performs LDADDA and later updates the owner byte; selected uncontended shadow words end at `0x01010000`. Cache/zone lock-acquisition helpers are modeled, so their source unlock-byte updates do not prove a real lock lifetime. Lock contention, wakeups and native preemption remain untested. [ZR4,ZR7]

## Partial-page, bitmap and element-address contract

The selected deeper fill executes original page admission, ownership checks, bitmap selection, element-pointer stores, metadata/count changes and partial/full-list transitions. It receives a declared zero 16384-byte arena and a consistent selected free-bit count; it does not obtain native storage. The original arena/page producer and global table provenance remain unknown. [ZR4,ZR6]

| Field | Selected declared value / original use |
|---|---|
| Zone `+0x9c`, u32 | Partial-page metadata index; source resolves the indexed 16-byte metadata record |
| Zone `+0xa0`, u32 | Full-page list head, populated when the selected page becomes full |
| Zone `+0xa8`, u32 | Available elements; original fill decrements by the number placed in current slots |
| Zone `+0xb0`, u32 | Reserve-related comparison input; declared 0 in the selected page epochs |
| Metadata `+0x00`, u16 | `0x1018`: selected one-granule encoding, fixed zone ID 24, external-bitmap mode |
| Metadata `+0x02`, u16 | Prior selected used count, then incremented by number of filled slots |
| Metadata `+0x04`, u32 | External bitmap descriptor 0; selected base offset 0 and one 64-bit word |
| Metadata `+0x08` / `+0x0c`, u32 | Next index / encoded previous-link location; source updates them when moving to the full list |
| Statistics `+0x18`, u32 | Allocation-selection cursor; source records each returned index |

Original page ownership decoding uses the metadata low 10 bits to reconstruct `zone_array_base + 192*ID`, then compares that address to the requested zone. Original pointer construction uses the signed page index shifted by 14, zone tail offset and selected index times element size. Here tail offset is 0 and element size is the source-created 256 bytes:

```text
element = (signed_page_index << 14) + 0 + selected_index * 256 bytes
```

The original file byte at `0xfffffe000ca92380` is `0xff`. The successful partial-page cases explicitly declare phase 0. With the same page/bitmap inputs and phase `0xff`, original fill preserves metadata and bitmap, supplies no current entries and reaches the held fallback. This is a falsification probe for the phase prerequisite; the actual native transition from the file value to an enabled phase remains unknown. [ZR1,ZR4]

The declared page index is derived from the private arena address, and a declared biased metadata-array base resolves it to private metadata. That bias is a component fixture, not an observed native metadata base. All selected element indices and resulting pointers stay inside the declared arena. [ZR4,ZR6]

| Page case | Initial used / available | Selected indices in fill order | Final used / available | Returned element index |
|---|---|---|---|---:|
| Ordinary partial page | 16 / 48 | 16 through 31 | 32 / 32 | 31 |
| Last available element | 63 / 1 | 63 | 64 / 0 | 63 |
| Cursor 63 with free low/high ranges | 16 / 48 | 0 through 15, after wrap | 32 / 32 | 15 |

The selector begins after the prior cursor and wraps over the declared bitmap word. Each selected free bit is removed and the cursor advances. The fill writes pointers in selection order; the original fast cache pop takes the last filled slot and clears it. This independently connects bitmap output, magazine publication and the final returned pointer. The full-page case removes the metadata index from zone `+0x9c`, inserts it at `+0xa0` and changes the encoded backlink accordingly. No object-list, index or pointer return is supplied by a whole-selector model. [ZR5,ZR6]

Three constrained scalar proofs establish the partial-fill capacity bound, one-bit removal for any nonzero u64 bitmap and the original reciprocal security-index calculation over its admitted selected array-index domain. The bitmap proof does not prove all cursor/search branches; the 33 selected calls have separate independent circular-selection oracles. Inline 32-bit and multiword bitmap modes remain unexecuted. [ZR6,ZR8]

## Component outcomes and remaining ABI boundary

| Case | Input epoch / variation | Original outcome | Visits |
|---:|---|---|---:|
| 0 | No inventory or available page elements | Refill returns no cache; stops at original fallback with nesting 1 | 84 |
| 1 | One shared full magazine, quota 0 | Current exchange, pop and constructor return | 178 |
| 2 | Two shared full magazines, quota 0 | One shared full remains; old current becomes shared empty | 177 |
| 3 | One local full magazine, quota 2 | Local shortcut; shared depot untouched | 165 |
| 4 | Same, four local empty magazines | Shortcut bypasses spill; local empty count becomes 5 | 165 |
| 5 | Two shared full magazines, quota 2 | Transfer to local inventory and consume first | 238 |
| 6 | Case 5 plus selected security bit 12 | Alternate insertion branch; equal final list state | 237 |
| 7 | Partial page with 48 available elements | Original 16-slot bitmap-backed fill and constructor return | 1169 |
| 8 | Partial page with one available element | One-slot fill and partial-to-full page transition | 344 |
| 9 | Cursor-wrap partial page | Original wrapped selection, 16-slot fill and return | 1176 |
| 10 | Exhausted local full list, four local empties, two shared full magazines | Spill three empties; transfer one full; return | 260 |
| 11 | Case-7 page inputs with original-file phase byte `0xff` | No bitmap/page change; held fallback | 80 |

Every returning case retains the producer's actual saved caller stack, restores its original callee-saved GP registers/SP, drops nesting to 0, checks all 256 bytes of the selected raw element and returns the original class-0 constructor field image. The raw arena stays zero and its external guard remains `0xa5`. Available-state accounting and cursor changes are distinct from the fast allocator's 256-byte allocation statistic. Cases 0 and 11 are held fallback prefixes, not returned errors or completed unwinds. [ZR2,ZR5,ZR7]

This advances a deeper facility used by the existing [original kmsg construction and notification path](kernel_kmsg_allocation_report.md). It does not execute a new notification queue, establish a new incoming/outgoing Mach endpoint or emit a native Mach message. Zone ID 24 remains an allocation/type domain. Existing static emission sites and the historical zut trace retain their original bounds; authentic daemon/kext transport, page backing/retirement and hardware authentication remain unknown. [ZR7]

## Assumption register and falsification probes

| ID | Assumption / dependent results | Stress test or falsification probe |
|---|---|---|
| ZR1 | Pinned KC bytes and logical fixup interpretation identify this build; all static roles depend on it | Rehash input; recapture every complete body, selected role and original control-global bytes; compare another build separately |
| ZR2 | Published held-prefix output is the continuation origin | Freshly replay that prefix; compare complete GP/SP/NZCV/SIMD/RAM and image-global transfer, including held nesting and saved caller frames |
| ZR3 | Declared full/empty magazines, link boundaries, quota and security bit are component inputs | Recover their actual inventory/configuration producers; verify native object uniqueness and list invariants before attributing these epochs to a live system |
| ZR4 | Raw zero arena, biased metadata/bitmap bases, phase and lock-model effects satisfy selected code | Replace the arena/global fixtures with source-produced page creation and actual lock/global-state producers; native admissibility remains unknown |
| ZR5 | Independent list/field/selection oracles describe the selected contracts | Check all source writes and before images; test local shortcut separately from exhausted-local spill; verify full/empty counts, boundary cells, consumed slots and returned pointer |
| ZR6 | One-granule, external one-word bitmap and supplied used/free counts are the admitted page epochs | Recover page initialization and bitmap construction; independently check bit counts, circular selection, owner ID, address bounds and partial/full backlink transitions |
| ZR7 | Logical PAC, shadow atomics and ABI-preserving lock models do not establish native synchronization or transport | Validate real keys/modifiers, contention, preemption, backing, rights, delivery and lifetime independently; retain fallback as a prefix stop |
| ZR8 | Complete source capture plus finite replay is bounded evidence | Extend only to source-admitted branches with their prerequisites; retain inline/multiword/callback/page-supply paths as unexecuted rather than promoting them to observed behavior |

## Bounded further context

| Impact | Finding / remaining opportunity | Consequence |
|---|---|---|
| High | Empty startup cache can reach original bitmap-backed allocation without a whole-fill return model | Original address/count/list computation is now checked; raw page/bitmap creation remains the next storage-provenance gap |
| High | Saved original constructor frames survive the refill continuation | The join proves caller continuity under explicit data overlays, not merely a standalone refill return |
| Medium | Active quota and startup-computed bound occupy different fields | Recover writers of zone `+0x7c`; do not infer runtime local-depot policy from startup bound `+0x7e` |
| Medium | Local full inventory bypasses shared spill | Quota thresholds alone do not determine the next transition; list availability changes control flow |
| Medium | Shared/local list fields encode a full/empty partition boundary | Treating them as ordinary tails misidentifies ownership and list-update effects |
| Low | Empty supply reaches original fallback while nesting is held | Further fallback analysis must preserve this context and the real saved caller frames |

## Reproduction, independent validation and quality gates

```sh
cd /Users/___/dev/dylex/extracted
export PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages
export Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_zone_refill.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_zone_refill.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_zone_refill.py
```

Static capture adds three complete routines / 779 instructions to the retained 16 functions. Independent replay imports no probe executor and verifies 4273 original instruction visits, 1363 reads / 9138 bytes, 583 writes / 3951 bytes, ten lock-call models, 105 refill/fill/selection frames, 30 allocation frames, 12 final boundaries, 384 SIMD registers, 12 system-register values, 2932 final global bytes and 12582912 final RAM bytes. Independent oracles cover all zone/cache/statistics bytes, 127 explicit patch before images, 33 selector returns, three page states, ten full zero checks, the genuine spill case, local shortcut and original-file phase gate. Three bounded scalar queries return `unsat`.

Recovery costs O(image + captured source) time/space. CPU/effect validation costs O(image + visits + RAM + effects) time and O(image + one RAM map + journals) space. Independent circular selection costs O(filled_slots * 64) time and O(filled_slots) space for the selected one-word mode. Solver expressions/domains are retained; no solver-complexity bound is asserted.

QG1: no normative conclusion required. QG2: ZR1-ZR8 record dependent assumptions and falsification probes. QG3: new routine roles, exact held-state continuation, magazine/page ABI and Mach-emission boundary covered for this increment; full interface investigation remains active. QG4: extents, offsets and strides are bytes; counters, masks and index widths are explicit and reproducible. QG5: local shortcut versus spill, quota versus bound, partition versus tail, supplied arena versus created storage and held fallback versus return are distinguished. QG6: original KC bytes, complete bodies, exact producer transfers, independent state oracles and full CPU/effect replay provide verified local provenance. QG7: bounded extensions and impact labels are recorded above. Scoped gates pass; native full FairPlay continuity remains unknown.
