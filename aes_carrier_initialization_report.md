# AES carrier initialization: allocation request, constructors and status provenance

Original source now connects the 144-byte command type view to `_OSObject_typed_operator_new`, its lower allocator boundary, original `IOCommand` base construction and provider seeding of 32 carriers. Eight constructor cases establish that construction leaves carrier+0x78 unchanged. The allocation wrapper requests raw flag 4, corroborated as `Z_ZERO` by separately versioned Apple source. This supports allocation initialization as the initial-zero explanation; actual allocator memory, runtime status writers and hardware completion remain unknown. [CI1-CI8]

```text
Original provider seeding loop, 32 iterations
  -> original typed allocation wrapper(view,144)
       -> lower typed backend(view,4) [DECLARED zeroed result]
       -> original requested-byte accounting addition
  -> original IOCommand base constructor: word+8 = 1; base vptr
  -> original derived vptr publication
  -> class-bookkeeping model
  -> original outer pool return/linking

status +0x78:
  initial zero: declared zeroed backend result
  constructor: unchanged
  later common consumers: read u32 status
  authentic runtime writer / device-result correspondence: UNKNOWN
```

[Source, full text scan and reference identity](triage_evidence/aes_carrier_initialization_source.json), [16 conditional profiles](triage_evidence/aes_carrier_initialization_profiles.json), [independent replay/oracles](triage_evidence/aes_carrier_initialization_checks.json), [preservation](triage_evidence/aes_carrier_initialization_delivery.json) and [scoped gates](triage_evidence/aes_carrier_initialization_quality_gates.json) retain the evidence. The external actor state is case 0 of the [earlier pool profiles](triage_evidence/aes_command_pool_profiles.json). The [completion report](aes_completion_contract_report.md) remains the consumer-side result contract; its declared event statuses are not hardware results.

## Assumption register

| ID | Premise and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CI1 | The pinned collection supplies all captured source and type metadata. | Rehash it; recapture 43 functions / 2507 instructions, three import bindings and both complete text sections. Different builds require remapping. |
| CI2 | Type-view file bytes provide the recorded size low24=144; runtime zone/backing identity remains unknown. | Establish actual startup relocation, zone initialization and runtime view before inferring a native allocator instance. |
| CI3 | Zeroed backend results are declared model effects, replacing 0x5a-filled private reservations. | Compare an authentic allocator result and backing extent. The raw flag request and reference semantics do not independently prove native memory contents. |
| CI4 | Direct constructor inputs are writable 144-byte reservations with declared metaclass and initial bytes. | Recover authentic allocation and construction epochs. Paired zero/0x5a cases establish local write coverage, rather than native reachability. |
| CI5 | Prior source-produced pool/gate state transfers exactly; class bookkeeping and thread/lock effects remain modeled. | Recover native metaclass counts, ownership, lock state and scheduling. Do not infer native reference balance from the +8 store alone. |
| CI6 | PAC and decoded import/vtable pointers are logical representations. | Match original chain metadata and actual hardware authentication. No native PAC operation executes. |
| CI7 | A separately pinned Apple header corroborates flag names; its revision is not established as this collection's source. | Match the collection build to source or complete lower allocator semantics. Binary raw values remain independently established. |
| CI8 | The literal-offset scan covers both complete selected text sections, but not alias, indexed, overlapping wider access, indirect helper or other-driver closure. | Recover carrier-relative data flow and every helper/receiver before claiming there are no later status writers. |

## Primary bytes and exact allocation ABI

Collection: `kernelcache.macho`; SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Exact nlist names, compiler boundaries, instruction bytes and original import fixups are retained. No IDB is changed.

| Source object / routine | Original address | Established contract |
| --- | --- | --- |
| `IOAESAcceleratorCommand_ktv` local type view | `0xfffffe000858a4a8` | u32 word+0x2c has low24=0x90, or 144 bytes. The file's initial zone pointer is zero; native zone identity is unknown. |
| Command allocation import | `0xfffffe000858a598` | Resolves to `_OSObject_typed_operator_new`, `0xfffffe000c4458c4`. |
| Base-constructor import | `0xfffffe000858a648` | Resolves to `IOCommand::IOCommand(OSMetaClass const*)`, `0xfffffe000c51fb58`. |
| Class-bookkeeping import | `0xfffffe000858a678` | Resolves to `OSMetaClass::instanceConstructed()`, `0xfffffe000c4434ec`; operation remains modeled. |
| Typed lower backend | `0xfffffe000bcfeb8c` | Exact `_kalloc_type_impl` / `_kalloc_type_impl_external` aliases; X0=type view, W1=raw flags 4 on the normal request. |
| Generic fallback backend | `0xfffffe000bcfe5b8` | Unnamed original function; X0=0xfffffe0007f36938, X1=requested u64 size, W2=0x41004, X3=0. |
| Allocation-accounting cell | `0xfffffe000cb5b638` | Original wrapper uses an atomic 64-bit addition of requested size at `0xfffffe000c445918`. Native current value is unknown. |

The original wrapper reads low24(view+0x2c), then compares the full requested X1 with that value using an unsigned condition. Requests no greater than the recorded size select the typed backend; larger requests select the generic fallback. Seven cases stop before either backend: requested sizes 0, 143 and 144 select typed; 145, 4294967295, 4294967296 and 18446744073709551615 select fallback. The latter are scalar boundary probes only, with no attempted allocation. The 2^32 case retains its full u64 value at the fallback boundary.

Original `IOAESAcceleratorCommand::operator new(unsigned long)` at `0xfffffe000abfc374` forwards requested size and this exact type view to the wrapper. Its metaclass allocator at `0xfffffe000abfc308` requests 0x90 bytes explicitly. The provider's seeding fragment also requests that size through the original import stub.

Apple's pinned [zalloc.h](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/zalloc.h) defines raw 4 as `Z_ZERO` and describes zero-initialized returned memory; its `Z_WAITOK` is zero and `Z_NOFAIL` is 0x8000. The raw 4 request therefore corroborates an intended zero-initialized allocation, without supplying a native allocator result or proving source-revision identity. The source JSON records URL, SHA-256 `3a7bcfed6b5062574a33ac59e15dd97fc8c8a80cc45b37c67f52f5f112c739d9`, physical-line enum excerpts and the build-matching limitation. No no-failure or native OOM conclusion follows. [CI2,CI3,CI7]

## Constructor writes and refreshed seeding state

| Constructor entry | Variant | Source-established local effect |
| --- | --- | --- |
| `0xfffffe000abfc1cc` | C2, explicit metaclass | Calls original base constructor, publishes derived vptr, returns this. |
| `0xfffffe000abfc204` | C1, explicit metaclass | Same local writes; no class-bookkeeping call in this body. |
| `0xfffffe000abfc388` | C1, default | Calls original base constructor, publishes derived vptr and requests class bookkeeping. |
| `0xfffffe000abfc3e4` | C2, default | Same local writes and bookkeeping request. |

The original base constructor at `0xfffffe000c51fb58` stores u32 value 1 to object+8 at `0xfffffe000c51fb60`, then logically signs/publishes base vptr `0xfffffe0007f41558`. Each derived constructor subsequently publishes vptr `0xfffffe0008588d98`. In all eight paired zero/0x5a cases, final bytes 12..143 exactly retain their input values. Consequently the status word at +0x78 is not reset by these constructor bodies. The +8 word alone does not prove an entire native reference-management contract. [CI4-CI6]

The 32-object seeding case runs the original typed wrapper and base constructor instead of the earlier entry-level allocation/base-constructor models. At the lower typed backend, each explicitly declared zeroed result replaces a 144-byte 0x5a reservation. Original source then supplies the accounting update, base word, derived vptr and pool linking. The final outer pool has all 32 distinct carriers, newest at head and oldest at tail; each has +8=1 and status+0x78=0. Only the declared backend effect supplies zero bytes at the status field. Original source writes in this case do not overlap that field.

With a declared private counter epoch initially zero:

```text
32 objects * 144 bytes/object = 4608 bytes
```

All 32 original atomic additions match the cumulative requested-size sequence. This is requested-byte accounting, not measured heap footprint, physical allocation size, memory pressure or native usage.

Earlier published pool/provider/completion profiles retain their explicit base-constructor model and original hashes. The refreshed seeding snapshot has a stronger base-construction premise and a different +8 word. It has not yet been propagated through those later components or joined to a native FairPlayIOKit/daemon epoch. [CI3-CI6]

## Bounded status-access census

The scan independently decodes every byte of the selected IOCryptoAcceleratorFamily and AppleS8000AES `__text` sections: 8210 instructions total, with 106 and 113 compiler function starts respectively. It matches exact literal `#0x78` operands, excluding larger constants such as 0x789. Four matches remain:

| Exact PC | Instruction | Classification within the captured source |
| --- | --- | --- |
| `0xfffffe000abfd1a8` | `ldr w8, [x1, #0x78]` | Common quantum-completion status read. |
| `0xfffffe000abfd3fc` | `ldr w21, [x19, #0x78]` | Common synchronous queue/waiter result read. |
| `0xfffffe000abfd630` | `ldr w21, [x19, #0x78]` | Common callback status read. |
| `0xfffffe000abfe61c` | `stur q0, [sp, #0x78]` | Stack vector store in the internal-test routine; not a carrier-relative direct status writer. |

No exact-literal +0x78 operand occurs in the candidate driver text. This is a complete literal-operand census for those two sections, not a proof of no status writers. Address aliases, indexed addressing, wider overlapping stores, other drivers and helper calls require separate analysis. [CI8]

## Verification, continuation and scoped quality gates

Sixteen fresh independent CPU replays verify 7078 original instruction visits, 944 writes (7385 bytes), 1483 reads (11580 bytes), 479 logical authentication steps, 300 indirect edges, 164 declared API models, 16 boundaries and 704 final object images. Additional checks cover 39 allocation frames, seven backend frontiers, 40 base-constructor frames, all 32 accounting additions, constructor tail preservation and 32 declared zeroing effects totaling 4608 bytes. These finite checks establish reproducibility under the stated premises.

From the extracted directory, run `PYTHONPATH=triage_evidence "$PYTHON" -P triage_evidence/validate_aes_carrier_initialization.py`. Recovery additionally fetches the pinned Apple header; ordinary validation checks its recorded identity and captured excerpt without fetching it again. Algorithms use time O(image bytes + text bytes + source visits + journal effects) and space O(image bytes + captured text + journals + private RAM). Addresses/offsets are hexadecimal, byte counts are exact integers, and one byte is 8 bits. No timing or physical-register unit is inferred.

| Impact | Remaining evidence | Purpose |
| --- | --- | --- |
| High | Propagate the refreshed source-constructed pool through packing and completion consumers | Retires the older base-constructor premise in subsequent components while preserving exact carrier identities. |
| High | Recover carrier aliases/helper writes and authentic status initialization/reuse epochs | Establishes whether status can change after allocation and how it corresponds to real completion. |
| High | Recover runtime type-view/zone setup and actual backend zeroing | Connects the allocation request to authentic memory and owner extents. |
| High | Join synchronous waiter, native wakeup and reclamation | Establishes when the original kext constructor can resume. |
| Medium | Recover hardware-job/adapter constructors and register mapping | Establishes the candidate driver's resources and concrete receiver types. |
| Low | Extend constructor/reference bookkeeping beyond the currently modeled class operation | Resolves full native class/reference accounting. |

QG1: Descriptive technical evidence requires no normative decision.

QG2: CI1-CI8 enumerate premises, dependent results and falsification probes.

QG3: The increment covers carrier allocation/construction, precise allocator call ABI, refreshed seeding and a bounded status-access census. Full daemon/kext/native lifecycle recovery remains active.

QG4: The u64 size comparison, low24 type-size extraction, byte units, requested-byte accounting and scan/replay counts are explicit and reproducible.

QG5: Allocation-request semantics, declared backend memory, constructor writes and authentic completion are separated. Alias closure, native zeroing, failure behavior and later epoch joins remain explicitly unknown.

QG6: Original bytes/symbols/imports, exact object transfers, independent CPU/read/write replay and a separately identified primary Apple header provide provenance. Native allocation, synchronization, crypto, Mach IPC and PAC are not executed; no IDB is changed.

QG7: The impact-labelled continuation table identifies the remaining architectural joins. Scoped gate passage does not imply full interface recovery or authentic hardware completion.

## Separate hardware-provider allocation geometry

The [trace/wakeup report](aes_trace_wakeup_report.md) reuses this report's separately versioned raw-4/Z_ZERO provenance for a different allocation: the AppleS8000AESAccelerator class and type view both specify 2560 B. That exactly covers its software ring and cursor. It does not change the carrier's 144 B contract or establish native zeroed memory, derived-field preservation or provider lifetime (TW1-TW5).
