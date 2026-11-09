# Candidate AES hardware jobs: inner pool, IODMA objects and segment ABI

The candidate driver's original startup fragment creates a distinct inner command pool/gate and seeds 32 hardware jobs. Each 64-byte job receives two source-constructed 120-byte `IODMACommand` objects through original factory and legacy-initializer code. The deeper options initializer, allocation backends, selected references/locks and PAC remain explicit models. Native mapper configuration, DMA, device submission, interrupt activation and runtime provider identity remain unknown. [HP1-HP8]

```text
shared source workloop
  maintenance gate
  event chain: provider gate -> outer-pool gate -> inner-pool gate

provider+0xf8  -> outer pool: 32 common carriers, 144 bytes each
provider+0x158 -> inner pool: 32 hardware jobs, 64 bytes each
                   job+0x20 -> IODMACommand A, 120-byte request
                   job+0x28 -> IODMACommand B, 120-byte request
                   job+0x30 -> outer-carrier backlink, initially NULL
                   job+0x38 -> u16 tag, initially 0xffff

IODMA factory -> source metaclass allocation/constructor
  -> source legacy initializer -> 40-byte SegmentOptions
  -> declared deeper initialization result
callback OutputLittle64 -> 16-byte little-endian address/length record
```

[Original source, fixups, stubs and SDK identity](triage_evidence/aes_hardware_job_source.json), [ten profiles](triage_evidence/aes_hardware_job_profiles.json), [fresh independent replay/oracles](triage_evidence/aes_hardware_job_checks.json), [preservation](triage_evidence/aes_hardware_job_delivery.json) and [scoped gates](triage_evidence/aes_hardware_job_quality_gates.json) retain the evidence. The external actor state is case 2 of the [synchronous-wait profiles](triage_evidence/aes_synchronous_wait_profiles.json), preserving the refreshed source-constructed outer carriers. The [completion report](aes_completion_contract_report.md) supplies the later job-backlink/common-carrier source interface; that completion is not executed here.

## Assumption register

| ID | Premise and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| HP1 | The pinned collection supplies the captured source, symbols and import records. | Rehash it; recapture 58 functions / 4882 instructions, eleven bindings and five stubs. Different runtime builds require remapping. |
| HP2 | The startup fragment enters after preceding buffer/resource success, with a declared candidate receiver and mapper cookie. Full subclass construction/runtime matching are unknown. | Establish authentic predecessors, mapper, device, allocation and service identity before applying the fragment to hardware. |
| HP3 | Pool/gate metaclass allocation, extension and zeroed job/DMA backends are declared results; native allocator ownership/extents remain unknown. | Match authentic allocation/class initialization and memory contents. Backend zeroing replaces explicit 0x5a reservations in these cases. |
| HP4 | DMA metaclass vptr is nominal; the original file's zero zone cache/count selects the captured generic allocation path. Native startup may change them. | Recover runtime metaclass/zone setup and compare the allocator path. Private count/accounting epochs are explicitly initialized. |
| HP5 | Original factory and legacy initializer execute, but the deeper SegmentOptions initializer supplies a declared Boolean result with no effects. | Execute/recover actual mapper/specification setup before claiming a prepared or DMA-capable object. A returned object under the model is insufficient. |
| HP6 | Gate attachment, pool links and constructors are original source; class bookkeeping, selected retains/releases and lock operations retain declared outcomes. | Establish native reference counts, lifetime, exclusion and scheduling. A modeled release request does not prove destruction/accounting balance. |
| HP7 | Output callback cases use declared address/length values and a four-record private output extent. They are record-codec cases, not observed bus mappings. | Match a real generation caller, segment count/capacity and mapper result before applying the bytes to a device. |
| HP8 | PAC is logical; the local SDK corroborates names/layout but is not established as the collection's source revision. The fragment stops before interrupt-source creation. | Match hardware authentication, SDK/build identity and authentic activation/submission/completion epochs. |

## Original identities and resource boundaries

Collection: `/Users/___/Downloads/fpx/img4_dump/kernelcache.macho`; SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Exact nlist names, complete compiler function ranges, bytes and original chained records are retained. No IDB is changed.

| Binding / routine | Original location | Exact target / source meaning |
| --- | --- | --- |
| Candidate startup | `0xfffffe0009d4ead0..0xfffffe0009d4f558` | `AppleS8000AESAccelerator::start(IOService*)`; complete source captured, bounded fragment executed. |
| Candidate virtual getWorkLoop | slot `0xfffffe00082fdf30` | `0xfffffe000abfcd54`, inherited `IOAESAccelerator::getWorkLoop() const`; source returns stored workloop. |
| Inner-pool factory import | slot `0xfffffe00082fe5c0`, stub `0xfffffe0009d52b64` | `0xfffffe000c520c24`, `IOCommandPool::withWorkLoop(IOWorkLoop*)`. |
| Job allocation import | slot `0xfffffe00082fe580`, stub `0xfffffe0009d52ae4` | `0xfffffe000c4458c4`, `_OSObject_typed_operator_new`. |
| Job type view | `0xfffffe00082fe528` | Exact local `IOAppleS8000AESAcceleratorCommand_ktv`; size low24=0x40. |
| Job base constructor | slot `0xfffffe00082fe600`, stub `0xfffffe0009d52be4` | `0xfffffe000c51fb58`, original `IOCommand` constructor. |
| Job class bookkeeping | slot `0xfffffe00082fe628`, stub `0xfffffe0009d52c34` | `0xfffffe000c4434ec`, `OSMetaClass::instanceConstructed()`; operation modeled. |
| DMA factory import | slot `0xfffffe00082fe5b0`, stub `0xfffffe0009d52b44` | `0xfffffe000c529b0c`, legacy `IODMACommand::withSpecification(...)`. |
| Segment callback import | slot `0xfffffe00082fe670` | `0xfffffe000c529dd8`, `IODMACommand::OutputLittle64(...)`. |

Ten of the eleven captured bindings are authenticated format-8 records. The callback import is format 8 with auth=0; startup signs the loaded callback for a function-pointer domain using raw discriminator 0xb692 before passing it to the factory. Logical source replay does not establish hardware PAC acceptance.

The executed fragment is `0xfffffe0009d4f1e8..0xfffffe0009d4f360`. Original source obtains the shared workloop, constructs/initializes a new inner pool and attaches its gate through the existing workloop maintenance path. Its provider+0x158 pointer differs from provider+0xf8. Original event-source links extend the existing provider-gate -> outer-pool-gate chain with the inner-pool gate. The maintenance gate remains separate. Both pool gates have their respective pool as owner and use explicit gated actions with NULL default action.

The outer pool object and all 32 common-carrier images remain byte-identical through these cases. The outer-pool gate's event-source next link changes to include the newly attached gate; this is an intended source topology update. Physical locks and native registration remain unproved. [HP2,HP3,HP6]

## Source job and pending-queue initialization

The original loop counter is 0x20. Each iteration requests 0x40 bytes with the job type view, runs the original allocation wrapper and base constructor, publishes job vptr `0xfffffe00082fe2a0`, requests class bookkeeping, constructs two DMA objects and returns the job through the inner pool's original gate/list path.

| Job field / state | Original writer | Established initial value |
| --- | --- | --- |
| Base u32 word+8 | `0xfffffe000c51fb60` | 1 |
| Derived vptr | `0xfffffe0009d4f260` | `0xfffffe00082fe2a0` under logical PAC |
| +0x20 adapter A | `0xfffffe0009d4f2a4` | First factory result in the iteration |
| +0x28 adapter B / +0x30 backlink | `0xfffffe0009d4f2cc` | Second factory result / NULL |
| u16 tag+0x38 | `0xfffffe0009d4f2d0` | 0xffff |
| Inner-pool return call | `0xfffffe0009d4f310` | Original source inserts the same job |
| Provider u16 +0x160 | `0xfffffe0009d4f31c` | 0 |
| Provider words +0x164/+0x168 | `0xfffffe0009d4f328` | 0xffffffff / 0; one 64-bit store from a zero-extended W9=-1 |
| Pending hardware-job queue +0x140/+0x148 | `0xfffffe0009d4f35c` | Both point to provider+0x140 sentinel |

All 32 jobs and 64 DMA object identities are distinct in the declared allocation sequence. The source inner pool leases the most recently seeded job, clears its links, and preserves both adapter pointers, null backlink and tag. Returning it restores all 150 private object images and both transferred source-global snapshots exactly to the seeded state. This is a finite source identity check, not native capacity or ownership proof.

The subsequent interrupt-source creation is outside the executed fragment. No MMIO, interrupt activation, crypto operation or hardware queue submission occurs. [HP2,HP3,HP6,HP8]

## DMA construction, factory and initializer ABI

| Source routine / binding | Exact location |
| --- | --- |
| `IODMACommand::withSpecification` legacy factory | `0xfffffe000c529b0c..0xfffffe000c529c08` |
| DMA metaclass object / nominal vptr | `0xfffffe000cb52ea8` / `0xfffffe0007f41450`; original object bytes zero |
| Metaclass +0xa8 allocator slot / target | `0xfffffe0007f414f8` -> `0xfffffe000c529048` |
| DMA instance vptr | `0xfffffe0007f411f8` |
| Legacy initializer +0x140 slot / target | `0xfffffe0007f41338` -> `0xfffffe000c528c08` |
| Options initializer +0x1a0 slot / target | `0xfffffe0007f41398` -> `0xfffffe000c526b48`; declared result boundary |

The original metaclass allocator reads a zone-cache pointer at `0xfffffe0007f41438`. Its file value is zero, selecting a generic backend request of 120 bytes with raw flags 0x41004 in these components. Declared zeroed memory is followed by original source writes: base word+8=1, DMA vptr, zero pointer words +0x40/+0x48, and an atomic increment of the private DMA metaclass count at +0x24. Native zone/metaclass startup and actual allocator contents are not established.

The two factory calls in every startup iteration have the same scalar ABI:

| Register | Original input |
| --- | --- |
| X0 | `OutputLittle64` callback, logically signed with discriminator 0xb692 |
| W1 | Address-bit parameter 0 |
| X2 | Maximum segment-size parameter 0 |
| W3 | Mapping-options code 0 |
| X4 | Maximum transfer-size parameter 0 |
| W5 | Alignment parameter 1 |
| X6 | Provider+0x1b8 mapper pointer; declared cookie in these profiles |
| X7 | RefCon NULL |

The legacy factory shifts these arguments for the instance method and places RefCon on the stack. Original legacy `initWithSpecification` then builds and forwards this 40-byte record:

| Offset | Width | SDK-correlated field | Source-generated value |
| --- | --- | --- | --- |
| 0x00 | u8 | fStructSize | 40 |
| 0x01 | u8 | fNumAddressBits | 0 |
| 0x08 | u64 | fMaxSegmentSize | 0 |
| 0x10 | u64 | fMaxTransferSize | 0 |
| 0x18 | u32 | fAlignment | 1 |
| 0x1c | u32 | fAlignmentLength | 1 |
| 0x20 | u32 | fAlignmentInternalSegments | 1 |

Padding bytes are source-zeroed. The deeper call receives X0=DMA object, X1=callback, X2=record pointer, W3=mapping code 0, X4=mapper and X5=RefCon NULL. All 66 captured option records match independently reconstructed bytes. The source JSON pins the local `IODMACommand.h` path/hash; field names corroborate the original instruction-generated layout, rather than establishing an exact matching SDK build or native bus width.

For a declared true options result, the original factory returns the constructed object. For false, it requests virtual release then returns NULL. A separate declared NULL metaclass-allocation result takes the factory's early NULL branch. Release, deep initialization and native memory pressure are not executed; allocator/reference balance remains unproved. The driver seeding case supplies true initialization outcomes throughout. [HP3-HP6,HP8]

## Segment output ABI and byte accounting

`OutputLittle64` is seven original instructions. Its observed input registers are X0=target, X1=64-bit address value, X2=64-bit length value, X3=output base and W4=index. It computes a byte offset using a 32-bit left shift by 4, stores X1 and X2 as adjacent 64-bit words, then returns W0=1. The target pointer is not dereferenced in this body.

Four bounded cases use indices 0-3 within a declared 64-byte output array. Independent byte oracles verify exactly one 16-byte little-endian address/length record and preservation of every other byte. Inputs include values above 2^32 to establish u64 preservation. These are opaque codec values; no corresponding physical mapping, transfer extent or bus transaction is supplied. Real caller capacity and mapper constraints remain separate premises. [HP7]

With a declared accounting epoch initially zero, original allocation-side atomic additions produce:

```text
32 jobs * 64 bytes/job = 2048 bytes
64 DMA objects * 120 bytes/object = 7680 bytes
2048 bytes + 7680 bytes = 9728 requested bytes
```

The original DMA metaclass count reaches 64 in the seeded component. These values are private source accounting, not native heap footprint, physical memory use or full reference balance. Pool/gate metaclass allocations and deeper initializer effects retain separate model premises.

## Verification, continuation and scoped quality gates

Ten independent fresh A64 replays verify 16660 original instruction visits, 3465 writes (25126 bytes), 3554 reads (27878 bytes), 1004 logical authentication steps, 583 indirect edges, 307 declared API models, ten boundaries, 1500 final object images and 20 source-global images. Additional checks cover 67 factory frames, 66 option packets, 32 job base-constructor frames, 34 inner-pool action frames, lease/return restoration, outer-resource preservation, pending-queue/tag initialization and four source segment-codec cases.

Reproduce from the extracted directory with `PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_aes_hardware_job.py`. Algorithms use time O(image bytes + source visits + journal events + objects) and space O(image bytes + journals + private RAM). Offsets/addresses are hexadecimal; byte counts and counts are exact integers; one byte is 8 bits. No duration or physical bus width is inferred.

| Impact | Remaining evidence | Purpose |
| --- | --- | --- |
| High | Join original performAESQuantum inner-pool lease to descriptor binding and transfer preparation | Carries the recovered job/adapter identities into the actual submission interface. |
| High | Recover deeper options/mapper initialization and authentic descriptor backing | Establishes real mapping, segment constraints and DMA readiness. |
| High | Recover hardware status producer, native interrupt/event epoch and original constructor join | Connects device output to the established common callback/synchronous result contract. |
| Medium | Recover native metaclass/zone startup and full reference teardown | Establishes runtime allocation path, release effects and object lifetimes. |
| Medium | Recover register mapping and interrupt-source creation/attachment | Establishes actual device resources and execution context beyond the current fragment. |
| Low | Extend valid segment-count/shape coverage with actual caller capacities | Broadens codec/mapper coverage without implying a device transaction. |

QG1: This increment requires descriptive technical evidence only.

QG2: HP1-HP8 enumerate assumptions, dependent results and falsification probes.

QG3: The increment covers hardware-job/adapter origins, separate pool/gate topology, source construction, scalar/options/segment ABI, conditional factory branches and bookkeeping. The broad daemon/kext/native goal remains active.

QG4: Object-size requests, u16/u32/u64 widths, exact packet offsets, byte arithmetic and replay counts are explicit and reproducible.

QG5: Source construction, declared allocation/init outcomes, source accounting and native readiness are separated. Zone/runtime identity, mapper effects, reference balance and device/status epochs remain explicitly unknown.

QG6: Original bytes/symbols/fixups, source-produced object/global transfers, separately identified SDK declarations and fresh CPU/read/write replay provide provenance. No native allocation, DMA, MMIO, interrupt, Mach IPC or PAC executes; no IDB changes.

QG7: The impact-labelled continuation table identifies the remaining architectural joins. Scoped gate passage does not establish native provider identity, prepared DMA, hardware completion or constructor/daemon continuity.
