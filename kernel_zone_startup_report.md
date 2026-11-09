# Original fixed-zone startup and embedded IPC allocation views

Original startup metadata and its callback now establish the static identity of the `ipc kmsgs` allocation zone. The allocator's two-word input at `0xfffffe000caec680` is the leading embedded view of a 192-byte zone record: a self pointer followed by per-CPU statistics. It is no longer merely an adjacent size/name candidate. Original creation and cache-initialization instructions construct that view in private shadow memory; the original message allocator then consumes it. Native bootstrap state, cache population, storage, locking and authentication remain unknown. [ZS1-ZS8]

Evidence: [original source and 70 startup records](triage_evidence/kernel_zone_startup_source.json), [10 CPU components](triage_evidence/kernel_zone_startup_profiles.json), [recapture, independent replay and three scalar proofs](triage_evidence/kernel_zone_startup_checks.json), [delivery seal](triage_evidence/kernel_zone_startup_delivery.json), [quality gates](triage_evidence/kernel_zone_startup_quality_gates.json). Kernel collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Original local files suffice; no IDA access, IDB/memory-store write, target launch or native IPC occurs.

## Startup metadata and anonymous routine roles

| Address | Established role | Evidence boundary |
|---|---|---|
| `0xfffffe000c63222c` | Startup callback decodes a zone specification, invokes the creator and optionally stores its returned pointer | Complete 16-instruction body; seven returning component executions |
| `0xfffffe000bd772b4` | Zone creator; selects a fixed 192-byte record, initializes metadata/statistics/cache, publishes its self view and returns the zone | Complete 568-instruction body; selected fixed-ID paths executed |
| `0xfffffe000bd77bb0` | Per-CPU cache initializer; obtains storage/magazines, writes empty current/spare views and publishes the cache pointer | Complete 77-instruction body; six executed components |
| `0xfffffe000cbea3c8` | Original startup entry for `ipc kmsgs` | Raw 24 bytes, callback and argument fixups recaptured |
| `0xfffffe000cbea3d0` | Authenticated callback-pointer slot targeting `0xfffffe000c63222c` | Format 8, auth 1, key index 0, diversity `0x2abe`, address-diversity 0; hardware authentication untested |
| `0xfffffe000cbea3d8` | Argument-pointer slot targeting specification `0xfffffe000cbc8310` | Original unauthenticated format-8 fixup |

Exact original symbols for the three newly captured routines are absent. The role names above describe recovered behavior; they do not assert recovered source names. The startup entry's two numeric words are 7 and 3. The extractor catalogs all 70 fixup references to this callback, including their argument specifications and owning sections. Actual startup-engine traversal/order is unknown; numeric metadata and address order do not prove execution order. [ZS1,ZS2]

The callback itself establishes the following 48-byte specification layout in `__BOOTDATA,__init`:

| Byte offset | Field | Original callback use |
|---|---|---|
| `+0x00` | Nullable publication-cell address | Loaded after creator return; conditional pointer store at `0xfffffe000c63225c` |
| `+0x08` | Name pointer | Creator X0 |
| `+0x10` | Requested size, u64 bytes | Creator X1 |
| `+0x18` | Flags, u64 | Creator X2 |
| `+0x20` | Identifier, u16 | Zero-extended creator X3 |
| `+0x28` | Nullable setup-object pointer | Creator X4; non-NULL invocation path captured but unexecuted |

| Original name | Specification | Fixed ID | Requested bytes | Numeric flags | Fixed zone/view address |
|---|---|---:|---:|---|---|
| `ipc ports` | `0xfffffe000cbc8340` | 22 | 144 | `0x02000011` | `0xfffffe000caec500` |
| `ipc port sets` | `0xfffffe000cbc8370` | 23 | 56 | `0x02000001` | `0xfffffe000caec5c0` |
| `ipc kmsgs` | `0xfffffe000cbc8310` | 24 | 256 | `0x02000010` | `0xfffffe000caec680` |

All three original IPC specifications have NULL publication-cell and setup-object fields. Their views arise inside the fixed zone array; the optional external publication store is unnecessary for these records. A separate controlled variant replaces the NULL publication-cell field and verifies the original store of the returned zone pointer. That variant is not an original IPC specification. The callback's residual X0 is not assigned a new status-code contract. [ZS2,ZS5]

## Fixed records, leading views and provenance refinement

The creator explicitly computes:

```text
zone(id) = 0xfffffe000caeb480 + 192 * id

startup spec -- original callback --> original creator
                                      |
                                      +--> zone +0x00 = zone itself
                                      +--> zone +0x08 = statistics base
                                      +--> zone +0x10 = name
                                      +--> zone +0x34 = rounded element size
                                      +--> zone +0x40 = logical cache base, when enabled
                                               |
original kmsg constructor LDP at 0xfffffe000bcc2680
  reads [0xfffffe000caec680, 0xfffffe000caec688]
  -> original zone-cache allocation -> original zero check -> original fields
```

The self-pointer store is at `0xfffffe000bd77708`; the statistics store is at `0xfffffe000bd7747c`; element size is stored at `0xfffffe000bd77590`. This directly connects original startup ID 24 to the input read by the original kmsg constructor. Previously described global zone/statistics pairs are embedded zone views in these selected fixed records. Original file zero values describe an uninitialized image, not a native runtime NULL allocation zone. [ZS1-ZS3]

| Previously used view | Array index from original 192-byte stride | Scope of new corroboration |
|---|---:|---|
| `0xfffffe000caec080` | 16 | Matches prior VM-map view/type-domain usage; creation caller remains unknown |
| `0xfffffe000caec2c0` | 19 | Matches prior VM-copy view/type-domain usage; creation caller remains unknown |
| `0xfffffe000caec500` | 22 | Original `ipc ports` specification and original creator output |
| `0xfffffe000caec5c0` | 23 | Original `ipc port sets` specification and original creator output |
| `0xfffffe000caec680` | 24 | Original `ipc kmsgs` specification, creator output and actual original consumer |

The five original 192-byte slot images are retained and recaptured. Earlier [VM-map initialization](kernel_map_store_init_report.md) and [VM-copy handling](kernel_vm_entry_copy_report.md) retain the corresponding caller/type-domain evidence. Allocation/type-domain IDs are distinct from Mach message IDs and task-local port names. A 192-byte zone metadata record is also distinct from its element size, such as the 144-byte IPC-port allocation. No new receive/send right, service endpoint, emission event or namespace conversion is established here. Prior static Mach emission sites and the historical zut capture retain their original evidence limits. [ZS3,ZS7]

This supersedes the unresolved static startup-consumer portion of the [previous allocation report](kernel_kmsg_allocation_report.md). Native runtime identity was not observed and remains unknown. The nearby `ipc_kernel_copy_map` tunable record is separate metadata; adjacency alone is not its linkage to this creator.

## Original creation and empty-cache contract

The selected bootstrap epoch declares at least 40 reserved fixed slots, an uncreated selected record, created count 0, phase word 0, a ready slot-2 allocation context and zero selected security metadata. The creator validates the requested extent against 32768 bytes and selects IDs below 40. Dynamic ID `0xffff`, duplicate creation, alternate phase/name handling and non-NULL setup-object paths remain unexecuted. [ZS2,ZS3]

For admitted requested extent `s`, original arithmetic computes `align_up(max(s,1),8)`. Thus the original IPC element sizes remain 256, 144 and 56 bytes; a controlled 257-byte request becomes 264 bytes. The selected paths use a 16384-byte allocation granule: their element counts are 64, 113, 292 and 62, with tail extents 0, 112, 32 and 16 bytes respectively. These are source-derived component values, not a measurement of the historical host page configuration. A constrained u64 proof checks rounding; a u32-ID proof plus explicit maximum-address bound checks fixed-slot arithmetic. [ZS3,ZS5]

The creator requests raw statistics storage through `0xfffffe000bd71a20(context,32,7)`. For the selected kmsg/port flags it also invokes the original cache initializer, which requests `(context,64,0x3f)` and two raw magazine allocations per declared CPU instance. Port-set flags take the no-cache path. Raw storage/magazine returns and lock effects remain explicit models; all metadata and cache-field stores are original instructions. [ZS3,ZS4]

| Field | Original initialized value under declared epoch |
|---|---|
| Zone `+0x7e`, u16 numeric cache bound | `min(budget / (magazine_capacity * element_bytes),32767)` |
| Cache `+0x00`, u32 | `0x144` |
| Cache `+0x04` / `+0x06`, u16 current/spare counts | 0 from declared zero storage; no startup fill |
| Cache `+0x08` / `+0x10` | First/second returned magazine pointers plus 16 bytes |
| Cache `+0x18` / `+0x20` | Zero |
| Cache `+0x28` | Address of cache `+0x20` |
| Per-CPU cache instance address | Base plus `(CPU_index << 14)` bytes |

The original cache loop advances by 16384 bytes per instance. With declared budget 1048576 and magazine capacity 16, numeric bounds are 256 for kmsgs, 455 for ports and 248 for the 264-byte controlled variant. Budget `0xffffffff` and capacity 1 exercise the 32767 clamp. For admitted element sizes and nonzero u16 magazine capacities, the maximum product is `32768 * 65535 = 2147450880`, below `2^32`; the capacity-range proof is independent of sampled quotients. Zero magazine capacity and other global epochs are outside the tested initialization contract. [ZS4,ZS5]

Before publication, original PACDA at `0xfffffe000bd77ca8` uses the cache pointer and modifier formed from zone `+0x40` with high 16 bits `0x8b6b`; the subsequent original store publishes it at zone `+0x40`. Logical PAC leaves a readable target in the shadow execution. It does not create or validate a hardware signature. [ZS6]

## Consumer handoff and tested frontiers

Three consumer components import the complete 1048576-byte startup RAM output and every captured startup image-global region. They retain the source-built zone metadata and its original leading view. A new call epoch supplies thread/CPU/pending state and raw object storage; filled-cache variants explicitly set current count 1 and its slot pointer. These are post-startup premises, not a recovered refill operation. [ZS3,ZS4]

| Case | Declared variation | Original outcome | Source visits |
|---:|---|---|---:|
| 0 | Kmsgs, one CPU instance | Startup callback returned; empty cache | 224 |
| 1 | Ports, one CPU instance | Startup callback returned; empty cache | 237 |
| 2 | Port sets | Startup callback returned; no cache | 157 |
| 3 | Kmsgs, two CPU instances | Both empty cache records initialized | 244 |
| 4 | Kmsgs, maximum budget/capacity 1 | Cache bound clamps to 32767 | 224 |
| 5 | Controlled non-NULL publication cell | Original callback publishes returned zone pointer | 225 |
| 6 | Controlled requested size 257 bytes | Original rounded element size 264 bytes | 237 |
| 7 | Original case-0 output, unfilled cache | Stops before original refill body, nesting 1 | 73 |
| 8 | Original case-0 output plus filled current cache | Original allocator returns 256-byte inline kmsg; nesting 0 | 166 |
| 9 | Original case-3 output plus filled CPU-index-1 cache | Original allocator returns kmsg; only selected statistics change | 166 |

Consumers enter the original constructor with `(44,0,0,1)`. Its LDP reads the actual source-built fixed view, and the zone-cache call receives `(zone,statistics_base,0x8004)`. Filled paths pop/clear the slot, add 256 to selected statistics, check every byte of the 256-byte raw object and return the original inline-class-0 field image. The guard byte after the object stays `0xa5`. Zone metadata and image globals remain unchanged. CPU-index 1 selects statistics/cache at a 16384-byte offset and preserves the other instance's statistics. No whole-zone, whole-kmsg, zero-check or consumer API return model occurs. [ZS3-ZS6]

The empty-cache component is a prefix stop at `0xfffffe000bd75e20`; it is not a successful allocation, an error return or a completed nesting unwind. Startup cache creation alone therefore cannot justify assuming a populated cache. Native refill, object initialization, deallocation/retirement and concurrency remain unknown. The previously established notification integration is retained in its [separate report](kernel_kmsg_allocation_report.md); this increment does not claim a newly executed startup-to-notification or daemon/kext end-to-end chain. [ZS4,ZS7]

## Assumption register and falsification probes

| ID | Assumption / dependent results | Stress test or falsification probe |
|---|---|---|
| ZS1 | Pinned original KC and logical fixup decoding describe the analyzed build; all static identities depend on this | Rehash KC, recapture complete bodies, 70 entry/specification pairs, original names, fixups and slot images; compare a different build separately |
| ZS2 | The callback can be analyzed with the declared reserved-slot bootstrap epoch; selected creator behavior depends on count/phase/security state | Run the actual startup engine/order with its real globals; separately admit dynamic-ID, duplicate, alternate phase and setup-object paths |
| ZS3 | Raw statistics/cache storage, zero origin, allocation-context readiness and lock models satisfy the selected original code | Replace primitive models with original storage/locking paths and their producing epochs; native ordering/lock ownership remains unknown |
| ZS4 | Raw magazine returns and explicit later filled-cache/thread state are admissible component inputs | Recover original magazine creation/refill and thread/CPU provenance; compare empty startup output against a source-produced populated cache |
| ZS5 | Controlled size/publication/budget variants test local contracts rather than original IPC metadata | Compare original specifications; independently verify 257-to-264 rounding, clamp and publication store; do not attribute variants to native startup |
| ZS6 | Logical PAC and declared call clobbers permit CPU modeling; native signatures are untested | Validate real keys/modifiers/signatures independently; replace primitive calls while preserving the calling convention |
| ZS7 | Component transfers retain full recorded RAM/globals but do not establish native transport or total object lifetime | Join actual allocation/refill/free producers and caller returns; correlate authentic daemon/kext exchanges and right ownership separately |
| ZS8 | Complete capture and finite replay are bounded evidence; source-level names/intention and unvisited paths remain unknown | Recapture exact bytes; independently replay all recorded effects and test additional source-admitted branches only when needed |

## Bounded further context

| Impact | Finding / remaining opportunity | Consequence |
|---|---|---|
| High | Source-created embedded views explain previously zero image cells | Separate uninitialized KC contents from runtime allocation metadata; static kmsg/port/port-set identities now have direct producer evidence |
| High | Source-built caches are empty | Recover original refill and raw-object initialization before extending successful allocation continuity |
| Medium | Startup itself allocates magazine objects through the same zone-allocation interface | Initialization has prerequisite allocator dependencies; callback metadata alone does not establish a boot dependency order |
| Medium | VM-map/copy view addresses follow the same fixed array stride | Recover their actual creation callers; address arithmetic alone does not establish their specifications or native state |
| Low | Optional external publication is absent in the three IPC specifications | Do not search for an IPC external-pointer store as a necessary startup step; the embedded self view supplies the consumer |

## Reproduction, independent checks and quality gates

```sh
cd /Users/___/dev/dylex/extracted
export PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages
export Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_zone_startup.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_zone_startup.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_zone_startup.py
```

Static capture retains 16 complete functions / 2732 instructions, including three new functions / 661 instructions. The independent replayer imports no probe executor. It checks 1953 original instruction visits, 489 reads / 3440 bytes, 401 writes / 2800 bytes, 67 primitive call models, 41 startup frames, 12 allocation frames, 10 final boundaries, 320 SIMD registers, three thread system-register values, 2316 final global bytes and 10485760 final private RAM bytes. Six logical data-signing and three logical authentication steps remain explicit. Three constrained scalar proofs return `unsat`; they are arithmetic contracts, not general reachability proofs.

Recovery costs O(image bytes + fixups + captured source) time and O(image + catalog + source) space. CPU replay/validation costs O(image + visits + RAM + journal effects) time and O(image + one RAM map + journals) space, excluding solver internals. Each fixed-width solver query records its exact domain and expression; no solver-complexity bound is asserted.

QG1: no normative conclusion required. QG2: ZS1-ZS8 record dependencies and falsification probes. QG3: anonymous roles, startup/consumer ABI, allocation-domain mapping and Mach-port evidence boundary covered for this increment; full investigation remains active. QG4: all extents/offsets/strides are bytes, numeric flags remain explicit and arithmetic bounds are reproducible. QG5: prior candidate ambiguity is resolved statically; empty-cache, controlled variants, prefix stops and native unknowns remain distinct. QG6: original KC bytes, fixups, complete bodies, independent field oracles and full-effect replay provide verified local provenance. QG7: bounded extensions and impact labels recorded above. Scoped gates pass; native full FairPlay continuity remains unknown.
