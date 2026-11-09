# Original range fallback and reservation rollback

Original caller fallback now completes for two declared map-flag epochs. The fast allocator returns `0x2e`; generic interval search returns a marked raw address with NULL allocation token, and consuming copyout completes through direct-entry store insertion. Separately, an exact source-produced reservation snapshot supplies the original rollback helper before any VM entry is inserted. Its nonzero-record path restores the last selected bit, unlinks the record, coalesces the pool range and requests record zeroing/release. This establishes conditional component contracts, not a live validator failure, native VM/ownership behavior or authentic FairPlay transport. [FR1-FR8]

Evidence: [76 complete functions /13296 instructions](triage_evidence/kernel_range_fallback_source.json), [19 private CPU components](triage_evidence/kernel_range_fallback_profiles.json), [fresh replay and exact state oracles](triage_evidence/kernel_range_fallback_checks.json). Original collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Original files suffice. No new IDA access, IDB mutation, saved-memory update, native target execution or native IPC occurs.

## Functions, ABI and original sites

Names below describe inferred roles rather than exact original symbols. Complete capture does not imply full branch coverage.

| Address | Inferred role | Selected coverage |
|---|---|---|
| `0xfffffe000bdde9ac` | Bitmap allocator / eligibility guards | Original map-flag guards return `0x2e` |
| `0xfffffe000bdc7434` | Class/range adapter and fallback routing | Original fallback and marked interval output |
| `0xfffffe000bdde280` | Forward generic interval search | Original two fallback searches and pool-reservation prefix |
| `0xfffffe000bde01b0` | Reservation rollback adapter | Zero-token/bit 63 guards; nonzero-record last-slot return |
| `0xfffffe000bde0334` | Return bitmap bits, maintain budget/list state and report all-free | Original single-record all-free path |
| `0xfffffe000bde0578` | Packed-store range removal/coalescing | Original selected root-level pool removal |
| `0xfffffe000bde0790` | Packed-store key/record deletion maintenance | Original selected scalar root update |
| `0xfffffe000bde0a1c` | Larger deletion/rebalance continuation | Captured; unexecuted |

| Original site | Contract |
|---|---|
| `0xfffffe000bdc755c` / `...7564` | Recognize fast result `0x2e` / enter fallback |
| `0xfffffe000bdc7658` | Call original forward search |
| `0xfffffe000bdcb58c` | Extract signed low 63 address bits with SBFX |
| `0xfffffe000bdcbb04` | Publish resulting output address |
| `0xfffffe000bdcba94` through `...baa0` | Static error path loads saved token and calls rollback `(map,raw_interval,record)` |
| `0xfffffe000bde01c4` / `...01cc` | Return immediately for raw address bit 63 / NULL record |
| `0xfffffe000bde01d8` through `...01f4` | Derive slot mask from record base/class; call bit-return helper |
| `0xfffffe000bde0348` | OR returned bit into bitmap |
| `0xfffffe000bde04d8` through `...04ec` | Selected all-free list unlink/accounting cleanup |
| `0xfffffe000bde02f0` | Remove/coalesce pool range in packed store |
| `0xfffffe000bde030c` / `...0330` | Request record zeroing / tail-call zone release |

These are local kernel interval/object/bookkeeping interfaces. Raw address bit 63, compressed record IDs, zone pointers and store hints are not Mach names, rights or message dispositions. No new message emission or daemon exchange occurs in these components. The historical zut failed-open trace remains unchanged. [FR2,FR4,FR8]

## Exact inputs and distinct component boundaries

The [source copy producer](kernel_vm_entry_copy_report.md) and [map/root constructor](kernel_map_store_init_report.md) are each reconstructed afresh. Three initial components receive the exact constructed primary RAM and auxiliary pages, with explicit bounds/cache/zone/map-flag fixtures. Sixteen later components transfer complete source-produced RAM, all three auxiliary pages and declared globals. Separate call registers are initialized explicitly. The logical copy extent remains 32769 bytes, page shift 14 and rounded entry width 49152 bytes. [FR2,FR3]

The initial components are two completed fallback copyouts and one fast-allocation prefix. That prefix stops at `0xfffffe000bdcb570`, after original range reservation returns `(D,record)` and before entry validation, relocation, unlink or publication. The input copy remains unchanged, the output address canary is untouched, and no VM entry belongs to the map yet. The map-lock request is modeled. The saved outer CPU context is not resumed after the separate rollback calls. [FR3,FR4]

```text
source copy + constructed map
  +-> declared map flag 8 or 0x100 -> original fast result 0x2e
  |    -> original generic search -> (marked interval, NULL token)
  |    -> original direct-entry insertion/release -> copyout return 0 -> lookup
  |
  +-> ordinary fast allocation -> source-produced reservation [stop]
       +-> separate rollback call with zero token -> pool data unchanged
       +-> separate rollback call with bit 63 set -> pool data unchanged
       +-> separate rollback call with produced pair
            -> return last bit -> unlink bucket -> coalesce pool
            -> record zero/free requests -> logical empty-store lookup
```

## Fallback marked-address ABI

Both declared map words are stored at map+0xb0. Their broader native flag names/authorization remain unknown. The source guards select fallback; no whole allocator or position-result model is used. Class bounds are declared R through R+1048576, with R=`0x6500000000`. Cached word `0x12345678` remains unchanged because these fallback paths allocate no bitmap record and consume no random word. [FR4,FR5]

| Declared map word | Fast result | Selected output D | Additional observed field |
|---|---|---|---|
| `0x8` | `0x2e` | R+0x4000 | Map+0xa0 becomes D+49152 |
| `0x100` | `0x2e` | R | Map+0xa0 stays zero |

The first address differs by one 16384-byte page. This is an observed branch result; no broader guard-page or flag-policy meaning is assigned. Both generic search calls receive `(map,R,R+1048576,0x6000000000000000,49152,0x3fff,out_pair)`. [FR4,FR5]

The raw result pair is `(D | 2^63, NULL)`, not simply `(D,NULL)`. Original copyout uses `SBFX ..., #0, #63`: it sign-extends bit 62 of the low 63 bits to recover the address representation. In these private fixtures D has bit 62 clear, so the published output equals D. This must not be generalized to unconditional bit 63 clearing for arbitrary native addresses. [FR4,FR6]

| Representation | Raw address bit 63 | Allocation token | Store representation |
|---|---|---|---|
| Original fast pool allocator | Clear | Non-NULL record | Tagged pool plus secondary candidate index |
| Original generic fallback | Set | NULL | Direct entry ID over[D,D+49152) |
| Earlier declared address-only component | Clear | NULL | Direct entry consumer branch; not proof of the original fallback marker |

The earlier [address-only model](kernel_map_store_init_report.md), the [record-producing allocator](kernel_range_resolver_report.md) and this real fallback therefore describe different premises and paths. Native addresses, class initialization and runtime map identity remain unestablished. [FR2,FR5,FR6]

Both fallback copyouts return zero. Original code releases the exclusive entry to word `0x10000`, restores thread nesting to 0 and requests zero/free of the consumed 48-byte wrapper. The root contains direct entry ID `0x40001`, map count 1 and 49152-byte accounting. Eight subsequent original lookups cover D-1, D, E-1 and E for E=D+49152. Before-start returns false with a candidate; inside returns true; E returns false/NULL. These are structural store results, not native access-right or payload proofs. [FR4,FR6,FR7]

## Reservation abort and last-slot cleanup

The fast prefix supplies D=R+0x80000 and record `0xfffffe00010000c0`. Original code has reserved a 1048576-byte pool, selected slot 8, changed bitmap `0xffff -> 0xfeff` and budget 12->11, and published the record in the class bucket. The 32-byte header is constructed, but the secondary candidate array is still zero because entry insertion has not run. The map entry count/accounting remain zero. [FR3,FR4]

The local rollback ABI is `(map,raw_interval,allocation_record)`. Three separate calls use the same produced data epoch:

| Call arguments | Original result for data objects |
|---|---|
| `(map,D,NULL)` | Early return; pool/record/bucket unchanged |
| `(map,D | 2^63,record)` | Early return; pool/record/bucket unchanged |
| `(map,D,record)` | Return selected bit, unlink all-free record, coalesce pool, zero/free requests |

The first two calls deliberately substitute guard arguments against the same reservation state. They are not asserted to be pairs produced by the original fast allocator. The helper's caller does not consume X0 as a status; raw return-register values from these standalone calls are not interpreted as success/error codes. Stack/register changes are distinguished from unchanged pool data. [FR4,FR6]

For the produced pair, original code derives slot 8 from the record's signed scaled base and class, then forms mask `1 << 8 = 0x100`. The bit-return helper stores bitmap `0xffff`; its all-free result sends the adapter into pool retirement. Original compressed-list checks pass, the bucket head becomes NULL and the record is removed from its circular list. The observed map-store coalescing range is 0 through `UINT64_MAX`, joining the adjacent empty intervals around the former pool. [FR4,FR6]

The selected record zeroing/free extent is 64 bytes, loaded from the supplied zone metadata. It remains a model-dependent observation extent, not an established native zone size. The input copy and its entry remain byte-identical. There is no successful entry publication to undo. [FR3,FR6,FR7]

Logical cleanup does not restore the complete earlier byte image. The root's active count returns to1 and its active boundary keys are 0 and `UINT64_MAX`, with record 0. Inactive boundary words and tag `0x80040003` remain beyond the active count, and map+0x50 retains its search hint. The cached random word remains consumed. Three real post-retirement lookups return false/NULL despite those inactive bytes. Two additional lookups against the retained pools from the guard probes also return false/NULL, since reservation alone supplied no entry candidate. [FR6,FR7]

The original copyout error branch statically passes the saved interval and record into this helper at `...bdcbaa0`. The current tests establish exact reservation-to-helper data continuity and helper behavior; they do not establish a live validation failure, uninterrupted outer error handling, native lock release or actual allocator retirement. [FR2,FR3,FR8]

## Assumption register

| ID | Assumption / dependent claims | Stress test or falsification probe |
|---|---|---|
| FR1 | Hash-pinned functions and original sites describe this build | Recapture all 76 bodies and exact caller/guard/bitmap/store/retirement instructions; verify runtime build pairing separately |
| FR2 | Normalized copy and generic map constructor are relevant component producers | Reconstruct both; join actual boot kernel-map and authentic caller/namespace/reply before full FairPlay claims |
| FR3 | Exact snapshots, overlays and separate call registers define the component handoffs | Compare all primary bytes/pages/globals; preserve the explicit pre-validation stop and avoid claiming resumed outer CPU continuity |
| FR4 | Declared map words, NULL objects, singleton pool/entry and guard substitutions bound these tests | Exercise real caller flag producers, other shifts/classes/records and actual validation-error prerequisites |
| FR5 | Valid private class bounds/cache/zone identities do not establish live native initialization or control | Recover boot/runtime writers and actual flag/entropy/provider semantics |
| FR6 | Signed-low 63 extraction, output token, bitmap/list/store oracles and active-count semantics compose selected paths | Verify raw/canonical values separately; cover nonempty neighbors, partial slot returns, larger deletion/rebalance and native address encodings |
| FR7 | Locks, allocation, byte moves, zero/free and logical PAC remain declared primitive outcomes | Independently derive effects and raw ABI; establish real zone extent, references, mappings, retirement and hardware authentication separately |
| FR8 | Nineteen cases and standalone abort do not establish a live error route or all interfaces | Continue genuine error propagation, reuse/exhaustion, rollback variants, non-NULL backing bytes and authentic kext/daemon transport |

## Verification and bounded continuation

Nineteen fresh CPU replays verify 4124 original instruction visits, 1078 reads /7435 bytes, 677 writes /5107 bytes and all 19 boundaries. Eighteen components return; one is the explicit pre-validation reservation stop. Replay compares 19 complete RAM images /19922944 bytes, 57 auxiliary-region records and 304 global records. Eighteen API models and ten effect patches /260 bytes pass. The patch total is `2*(8+4+48) + (64+8+4) + 64 = 260 bytes`: two fallback copyouts, reservation construction and record zeroing. Two additional fresh replays reconstruct source copy/map producers.

```text
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_range_fallback.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_range_fallback.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_range_fallback.py
```

Recovery/validation is O(image + captured bytes + visits + RAM + effects) time and O(image + source + RAM + journals) space. Primary RAM is 1048576 bytes per component; each auxiliary page is 4096 bytes. Compressed snapshots add retained storage. All stated arithmetic is exact in the tested domain; no statistical or native-performance claim is made.

| Impact | Bounded continuation | Additional evidence |
|---|---|---|
| High | Establish a genuine post-reservation validation failure and resume the original caller error path | Complete error-result, lock and ownership causality beyond separate helper calls |
| High | Reuse/exhaust pool records and return subsets of allocated slots | Budget/list transitions and partial versus complete pool retirement |
| High | Recover actual class bounds/map flags/provider initialization | Replace environmental identity/control premises |
| High | Recover non-NULL backing bytes and authentic FairPlay transport | Cross-layer payload and native ownership continuity |
| Medium | Larger store removal/rebalance, reverse search and native address encodings | Extend marker, lookup and coalescing semantics beyond singleton positive-base fixtures |

QG1: Factual technical analysis; no normative judgment required.
QG2: FR1-FR8 identify premises, dependent conclusions and falsification probes.
QG3: Scoped anonymous roles, original emission sites, fallback/marker/rollback ABI, data/control/lifetime/environment and respective report updates are covered. Full goal remains incomplete.
QG4: Explicit widths, signed extraction, bitmap/page arithmetic, byte counts, snapshot sizes, costs and commands are reproducible.
QG5: Marked interval versus published address, live pair versus guard substitutions, helper return versus status, held reservation versus inserted entry, inactive bytes versus active records and component versus native behavior are distinguished.
QG6: Original hashes/functions/sites, fresh producers, exact state/frame oracles and independent CPU/effect replay provide primary provenance.
QG7: Impact-labelled continuation remains bounded to unresolved error, allocator, environment, payload and FairPlay interfaces.

[Preservation](triage_evidence/kernel_range_fallback_delivery.json), [scoped gates](triage_evidence/kernel_range_fallback_quality_gates.json), [publication verifier](triage_evidence/verify_kernel_range_fallback_publication.py). The full goal remains active.
