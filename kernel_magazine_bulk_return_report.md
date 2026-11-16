# Bulk magazine return, metadata transitions and original-fill roundtrips

The original body at `0xfffffe000bd74bec` returns each cached object to its zone's free bitmap, updates metadata counts and encoded queues, optionally requests the existing observer/wake followup, and publishes the original batch count to the zone's available-object counter after completion. This establishes the per-object work behind the earlier [magazine drain](kernel_magazine_depot_drain_report.md) and [prefill](kernel_zone_prefill_callers_report.md) interfaces. Two original fill executions now produce the exact slot bytes consumed by four bulk/prefill components. Their explicit ownership handoffs are private new-call epochs; native storage, ownership transitions, authentication, exclusion, wake delivery and daemon transaction identity remain unknown. [KB1-KB7]

```text
original refill -> original fill -> original selector
                         |
                  exact produced slots
                         |
             declared ownership handoff
             + new bulk/prefill call epoch
                         |
      read slot -> clear slot -> validate range/zone/extent
                         |
       free bitmap bit -> metadata count -> encoded queues
                         |
       optional original followup -> modeled wake wrapper
                         |
             available += original batch count
                         |
      prefill: modeled magazine bzero + separate retirement
                         |
                  original Boolean progress
```

## Primary evidence and claims

Collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Normalized kext SHA-256: `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. All six complete bodies match preceding captures; this increment adds semantic recovery, execution and composition rather than new code discovery. None of their entry addresses has an exact original nlist definition; role names below are descriptive. The associated reference data sufficed; no new IDA access or mutation was required.

| Role | Interval, end exclusive | Instructions / bytes | SHA-256 |
| --- | --- | --- | --- |
| Bulk return | 0xfffffe000bd74bec..0xfffffe000bd74fcc | 248 / 992 B | 25b32ead83824f6e72457e4c1dc78dcd8c7c842b02b2410cd711e6ad87cee465 |
| Observer/wake followup | 0xfffffe000bd75b54..0xfffffe000bd75c64 | 68 / 272 B | 0826396e807e213139e78ee6a7a44d866dfa047ac634b89c43110016c5575da0 |
| Prefill | 0xfffffe000bd730f8..0xfffffe000bd7332c | 141 / 564 B | 8d65e179708af1b61ef3372310d16e0e5597e3ac790859790df19233a20285e3 |
| Refill | 0xfffffe000bd75e20..0xfffffe000bd76394 | 349 / 1396 B | 1b8d2d081dccb75ca16062e7b7ec8b390fd10724b53c1b84a19deb1ecfc1328d |
| Fill | 0xfffffe000bd76db4..0xfffffe000bd772b4 | 320 / 1280 B | 7895803a552950260eb276ca69579e80b8e688ee8e83be1d693ce5f0ca19fd13 |
| Selector | 0xfffffe000bd76ad0..0xfffffe000bd76c88 | 110 / 440 B | 49c9b59b4ddec5a5342ffe207c0a2378a171ece40d141881668dccad7ad076d5 |

| Claim | Established contract | Dependencies |
| --- | --- | --- |
| KB1 | Bulk ABI, slot custody and completion accounting | KB-A1-KB-A3 |
| KB2 | Range, zone, displacement and exact bitmap selection | KB-A1-KB-A4 |
| KB3 | Metadata count, encoded queues and diagnostic partial states | KB-A1-KB-A4 |
| KB4 | Original followup, volatile-input restoration and wake-request ABI | KB-A1-KB-A3, KB-A5 |
| KB5 | Original-fill-produced slots and declared direct/prefill roundtrips | KB-A1-KB-A6 |
| KB6 | Original prefill progress after separate magazine zero/retirement requests | KB-A1-KB-A3, KB-A5-KB-A6 |
| KB7 | Fresh local source proofs, independent whole-state checks and mutation controls | KB-A1-KB-A6 |

Evidence: [extractor](triage_evidence/recover_kernel_magazine_bulk_return.py), [source audit](triage_evidence/audit_kernel_magazine_bulk_return.py), [CPU and semantic oracle](triage_evidence/probe_kernel_magazine_bulk_return.py), [delivery verifier](triage_evidence/verify_kernel_magazine_bulk_return_delivery.py), [capture](triage_evidence/kernel_magazine_bulk_return_checks.json.zst), [audit receipt](triage_evidence/kernel_magazine_bulk_return_audit.json.zst). Decoded capture SHA-256: `cea5c2bb94a496f2bc53a2b4bc15f4233b3a7b42ccf3be8ee4a1c91b68586e09` (187,876 B). Decoded audit SHA-256: `8f0c6f9cc05de488a76395081022e41476d3a8857006061bf74f7d21ddce5e0d` (5,114,303 B).

## ABI, calls and data flow

Inputs are X0=zone Z, W1=original object count N and X2=pointer-slot array. The routine saves a 128 B frame including X19-X28 and FP/LR. Zero N bypasses the loop. Otherwise it initializes a u64 slot index and u32 remaining count. Each iteration reads u64[array+8*index] then clears that cell at `0xfffffe000bd74c60`, before validating the recovered pointer. Successful completion increments the index and decrements the remaining count. After all slots, u32[Z+0xa8] receives its old value plus the original N modulo 2^32. A diagnostic prefix does not publish the whole batch count. [KB1]

| Outgoing BL PC | Target | Recovered purpose |
| --- | --- | --- |
| 0xfffffe000bd74f60 | 0xfffffe000bd75b54 | Original observer/wake followup |
| 0xfffffe000bd74fa8 | 0xfffffe000c633aa0 | Pointer-range, zone or exact-extent diagnostic |
| 0xfffffe000bd74fb0 | 0xfffffe000c633728 | Reciprocal encoded-queue-link diagnostic |
| 0xfffffe000bd74fb8 | 0xfffffe000c633c7c | Already-free bitmap-bit diagnostic |
| 0xfffffe000bd74fc8 | 0xfffffe000c6338dc | Metadata-count underflow diagnostic |

These are internal calls. No additional Mach port endpoint, transmitted right or Mach message emission is established. The internal event address is Z+0x20; it is not a recovered Mach port name.

The pointer must lie in the unsigned half-open interval supplied by globals `0xfffffe0007e66e50` and `0xfffffe0007e66e58`. With metadata root R=u64[0xfffffe0007e66f00], the initial record is `R+((pointer>>10)&0xffffffff0) mod 2^64`. Its low ten header bits select the expected zone as `0xfffffe000caeb480+192*ID`. A mismatch requests the common range/zone/extent diagnostic. [KB2]

Displacement starts as `(pointer&0x3fff)-u16[Z+0x36] mod 2^64`. Extended header high nibble0xe000 supplies a byte at record+2: displacement gains byte*16384 B and the leading record moves backward byte*16 B. The source high-bit XOR gate can replace that record address's upper sixteen bits with0xc8a2. This address-tag branch has a source certificate; its MOVK instruction at `0xfffffe000bd74cd4` is the only one of248 bulk PCs not executed by these components. Native mapping of the resulting tagged address remains unknown.

Let `product=u64[Z+0x28]*displacement mod 2^64` and `index=product>>32`. The unsigned product of the low32 index and u16 extent must equal the full64 displacement. The leading metadata header bit11 then selects the bitmap representation:

| Layout | Word address | Word / mask |
| --- | --- | --- |
| External | u64[0xfffffe0007e66e70] + 8*(u32[meta+4]&0x0fffffff) + 8*(product>>38) | 64 bit / 1<<(index&63) |
| Inline | meta + 16*(product>>37) + 4 | 32 bit / 1<<(index&31) |

An already-set bit requests the diagnostic. Otherwise XOR changes that zero bit to one while preserving the other bits. The u16 count at meta+2 is decremented and stored before testing its old value for zero. Thus the zero-count diagnostic prefix has already cleared the slot, set the bitmap bit and stored0xffff. These are source-ordered private observations; native admission of inconsistent metadata is unknown. [KB2,KB3]

## Encoded queues and followup

A new low16 count of zero moves metadata to the empty queue at Z+0x98 and adds header>>12 to u32[Z+0x90]. Otherwise, a partial-queue move to Z+0x9c occurs exactly when `extent*((old_count&0x7fff)+1) > ((zero_extend(header)<<2)&0x3c000)`. The extension precedes the shift. Other nonzero counts leave the queue untouched. [KB3]

The record's next/previous encodings are u32 fields at +8/+0xc; its own ID is low32((meta-R)>>4). A signed-positive previous encoding selects the sentinel cell `G-4+4*previous`, G=0xfffffe000ca8c000. Other previous encodings select `R+16*zero_extend(previous)+8`. The code checks reciprocal links while detaching and inserting. Some checks follow earlier updates, so next-, previous- and destination-backlink failures have distinct partial states. The independent oracle preserves that ordering, including the empty-queue metadata-predecessor case; it does not impose atomic rollback.

After every processed object, the source reloads byte[Z+0x3c] bit4. When set, the original followup clears it, visits the declared empty observer list, hashes event Z+0x20 and tail-calls wrapper `0xfffffe000bd6e22c`. Its request is `(queue,event,0,0,0xffffffff)`. The wrapper is modeled as an ordinary zero return with no RAM effect; scheduler effects and native wake delivery remain unknown. The original followup and its hash execute, rather than a whole-followup return model. [KB4]

The bulk frame saves and restores volatile X0, W1, X2 and X15 around the followup. This preserves the original N for completion accounting despite the callback return. In the declared no-other-writer epoch, clearing bit4 suppresses additional notifications in the batch. Registered observers, callback interference and concurrent flag writers remain outside these components.

## Original fill producers and explicit handoffs

The original refill/fill/selector executions start from the earlier held-refill setup and stop at `0xfffffe000bd76294`, immediately after fill returns and before refill pops a slot or constructs an object. Both use the same private zone ID24, 256 B element extent, 16,384 B page and sixteen-slot producer capacity. Source-produced arrays contain precisely PAGE+(used+j)*256. [KB5]

| Before fill | After original fill | After original bulk | Queue effect |
| --- | --- | --- | --- |
| used16 / available48 | used32 / available32; 16 emitted slots | used16 / available48; original bitmap restored | Partial remains partial |
| used63 / available1 | used64 / available0; 1 emitted slot | used63 / available1; original bitmap restored | Partial -> full -> partial |

For each producer, both a direct bulk component and an original-prefill component consume the unchanged source-produced slot bytes. Admission transfers the producer's exact private RAM and globals, detaches current-cache slot ownership by setting its count to zero, supplies declared bulk range bounds and initializes a new GP/SP call frame. This is an explicit ownership handoff between private call epochs, not continuation of the same original caller stack or proof of a native ownership transition.

Prefill cases provide a one-full-magazine shared inventory and quota zero, so these particular joins bypass per-CPU drain. The sixteen-slot case declares capacity16 and a144 B magazine. The one-slot case deliberately changes capacity from the producer's16 to1 in the new call epoch and requests24 B within mapped144 B storage. That separate capacity-epoch control does not establish native capacity/type compatibility or a native capacity transition. Both direct bulk cases use the actual emitted count. [KB5,KB6]

Original prefill executes the actual bulk body, then requests bzero over the declared magazine extent and requests magazine retirement through a distinct zone/accounting pair. Zeroing is modeled with its exact extent; retirement is modeled with no RAM effect and return0xffffffff. The source nevertheless returns Boolean1, demonstrating that this progress result follows consuming a full magazine and is not the modeled retirement return. The bulk itself contains no application-payload bzero request. Physical reclamation and object lifetime remain unknown.

An independent refill replay engine checks both producer receipts without importing this probe executor. The used16 producer replays1055 visits,116 writes/833 B and166 reads/944 B; the used63 producer replays230 visits,46 writes/317 B and56 reads/314 B. Together these check2 MiB of private RAM,510 global bytes,64 SIMD register snapshots and two system-register snapshots, with the earlier declared API-lock models retained.

## Verification and assumptions

Twenty-one new source counterexample queries are UNSAT with SAT premises. They cover85 distinct source PCs,115 proof instruction instances and94 linked-edge obligations. Two generic separation lemmas are independently re-solved;208 checked typed read/store rewrites use the declared nonwrapping, owned, disjoint-region domain. These are selected source certificates, not a universal whole-bulk/list/maintenance proof. [KB7]

The44 private components execute9012 original source visits and cover247 of248 bulk PCs. They pass364 independent oracle checks across both bitmap layouts, N=0/1/2/16, count boundaries, cross-word bit positions, extended metadata, sentinel/metadata predecessors, destination lists, followup and diagnostic prefixes. The oracle independently reconstructs slot clearing, bitmap/count/queue state, the complete192 B zone and every private RAM byte outside [entrySP-512 B,entrySP+256 B). It also checks normal saved-GP/SP restoration, original wake hashing/request ABI, prefill progress and the four producer roundtrips. Expected state is not obtained by replaying source writes.

NOP substitutions at the actual slot-clear PC `0xfffffe000bd74c60` and completion-store PC `0xfffffe000bd74f80` each cause rejection by the independent oracle. These are changed-source CPU controls, not SMT SAT or native feasibility claims. PAC operations and authenticated returns use logical models; outer prefill locking, wake wrapper, magazine zeroing and retirement have the explicitly stated leaf models.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| KB-A1: pinned images | Exact collection/kext bytes and six matched bodies supply KB1-KB7. | Rehash, recapture and compare all six complete functions and dependency receipts. |
| KB-A2: instruction semantics | Widths, modular arithmetic, memory cuts and private CPU semantics supply KB1-KB7's modeled results. | Reconstruct and solve21 source queries, recheck two separation lemmas, independently replay producers and reject both NOP controls. |
| KB-A3: storage and ABI | Valid nonwrapping owned regions, ordinary call return and conditional PAC apply to KB1-KB7. | Verify native mappings, aliases, pointer authentication and ABI frames; separately exercise nonreturning calls. |
| KB-A4: metadata consistency | Finite coherent array/bitmap/count/queue premises bound ordinary KB2-KB3; diagnostic controls deliberately violate selected premises. | Compare both bitmap layouts, cross-word positions, extended records, threshold boundaries and reciprocal-link failure prefixes; investigate native producers separately. |
| KB-A5: external-effect epoch | Empty observers, no concurrent writers and declared lock/wake/retirement models bound KB4-KB7. | Recover observer registration, callback mutations, native exclusion and wake/reacquire ordering; replace each model with its actual callee before extending claims. |
| KB-A6: producer ownership/capacity | Explicit cache detach, range overlays and new-call frames bound KB5-KB7. The1-slot prefill is a separate capacity epoch. | Establish native magazine storage, allocation zone/type, fixed capacity and ownership transfer; compose without overlays or capacity changes before asserting a native-compatible transition. |

Byte checks:1236*4 B=4944 B captured;248*4 B=992 B bulk;85*4 B=340 B distinct certified cuts. Stack frame=128 B; normal16-slot magazine extent=16 B+16*8 B=144 B; one-slot control extent=24 B. Successful finite source processing is O(N) time and O(1) additional source space, excluding callback work. Extraction is O(B+I+S) time/space for bytes, instructions and symbols. Formula/replay/oracle construction is O(I+Q+V+J+R) time/space for instruction instances, formula DAG, visits, journals and RAM; solver search is separate with30 s/query limits. Integer arithmetic widths and selected memory extents are explicit.

## Bounded continuation

| Impact | Next evidence | Remaining question |
| --- | --- | --- |
| High | Native magazine/cache allocation, installation and fixed-capacity producers | Actual storage validity, ownership and compatible fill/drain/bulk epochs |
| High | Original nonempty observer traversal and wake/reacquire callees | Callback interference, native event delivery and synchronization |
| High | Matching daemon/userclient allocation and event epoch | Transaction-level daemon/kext correlation |
| Medium | Metadata queue consumers and magazine-retirement body | Physical reclamation, reuse and accounting-view identity |
| Medium | Complete maintenance admission and bit2/quota writers | All accepted controls and publication ordering |
| Low | Tagged leading-metadata mappings and indirect callers | Broader layout/caller completeness |

The full interface investigation remains active.

## Scoped quality gates

- **QG1**: Factual binary, ABI, data/control-flow and provenance analysis only.
- **QG2**: KB-A1-KB-A6 register dependent claims and falsification probes.
- **QG3**: Bulk semantics, calls/emission sites, external effects, environmental premises and producer composition are covered within this increment.
- **QG4**: Widths, byte extents, source counts and query/replay totals are reproducible.
- **QG5**: Source versus native behavior, partial diagnostics, capacity epochs, unexecuted tag PC and leaf models are explicit.
- **QG6**: Pinned bytes, exact previous matches, fresh source queries, independent replay/oracles and mutation controls provide provenance.
- **QG7**: Impact-ranked continuation identifies bounded remaining interfaces; native identity and whole-goal completion are not asserted.
