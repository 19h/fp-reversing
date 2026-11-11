# AES quantum: carrier/job binding, descriptor ranges and transfer consumers

Original `performAES` now reaches candidate `performAESQuantum`, leases a source-created inner job, publishes the outer-carrier backlink and passes the job's DMA adapters through descriptor binding/cache-operation calls. The normal cases stop before `_configureAES`. A declared configuration-error case verifies cleanup before a disable/register boundary. Separate transfer-helper consumers verify segment inputs and minimum-length selection before register access. Native activation, mapper/cache effects, configuration and hardware completion remain unknown. [QB1-QB8]

```text
published outer carriers + inner jobs/DMA objects
  -> original performAES -> outer lease C -> pack/queue/dequeue C
  -> original performAESQuantum -> inner lease J -> J.backlink = C
  -> original _enableAES(true), under declared already-enabled predicate
  -> outstanding bookkeeping +1
  -> bind J.DMA_A/B -> descriptor performOperation(2/1,offset,count)
  -> _configureAES(provider,C,0) [STOP; body not executed]

declared nonzero configuration return
  -> clear both DMA descriptors -> clear backlink -> return J
  -> decrement outstanding -> _enableAES(false)
  -> [STOP before register-base load; C remains leased]

separate _prepareTransfer inputs, not a configuration-success continuation
  -> request one segment from each DMA object
  -> declared segment records -> min(remaining,lenA,lenB)
  -> [STOP before register-base load]
```

[Original source, slots and SDK identities](triage_evidence/aes_quantum_binding_source.json), [13 profiles](triage_evidence/aes_quantum_binding_profiles.json), [fresh independent replay/oracles](triage_evidence/aes_quantum_binding_checks.json), [preservation](triage_evidence/aes_quantum_binding_delivery.json) and [scoped gates](triage_evidence/aes_quantum_binding_quality_gates.json) retain the evidence. External starting state is case 0 of the [hardware-job profiles](triage_evidence/aes_hardware_job_profiles.json), with 32 source-constructed jobs and 64 source-constructed nominal DMA objects. Allocation/deep mapper-initialization premises carry forward. No authentic configuration-success result is supplied.

## Assumption register

| ID | Premise and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| QB1 | The pinned collection supplies captured source and exact bindings. | Rehash it; recapture 61 functions / 5892 instructions and four slots. Different runtime builds require remapping. |
| QB2 | The receiver is the declared candidate instance; provider+0x1f8 bit 0 is explicitly supplied as 1 for the already-enabled branch, or 0 for the activation frontier. | Establish authentic activation, class, resources and flag publication. The fixture proves a source predicate branch, not device power state. |
| QB3 | Published object/global snapshots transfer exactly; a 0xa00-byte private provider reservation covers source trace accesses. Native allocation/owner extents are unknown. | Match real construction, object size, references, workloop and runtime epoch. This reservation extends the earlier 0x200-byte recorded prefix without asserting native extent. |
| QB4 | Key metadata, descriptor prepare/address, DMA bind/clear and cache-operation outcomes remain declared no-effect models. | Match actual caller data, descriptor extents, preparation, mapper binding and native cache outcomes. Returned registers alone do not establish actual success/failure effects. |
| QB5 | The configuration-error case substitutes a nonzero return with no effects at `_configureAES` entry. Its body and true effects are unknown. | Recover actual configuration and error provenance before applying this cleanup path to real state. No device/cipher result or public error return is established. |
| QB6 | Transfer-helper entries are separate declared consumers using recovered DMA identities and supplied arguments/records. They are not continuations through successful AES configuration. | Preserve an authentic caller/configuration/mapper epoch and join the actual segment producer before inferring native transfer readiness. |
| QB7 | Segment generation supplies explicit record, cursor and count outcomes; native mappings and record ownership are unproved. | Match real genIOVMSegments behavior, extents, capacity, count and physical/bus addresses. Finite positive lengths do not establish general mapper behavior. |
| QB8 | Locks/PAC retain earlier models; SDK declarations corroborate names but are not the matched collection source. Execution stops before device/register operations and assertion handlers. | Match native synchronization/authentication/build identity, actual activation, register resources and completion before a full constructor/daemon claim. |

## Primary bytes and precise interface names

Collection: `kernelcache.macho`; SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Exact symbols, compiler ranges and original bytes are captured. No IDB is changed.

| Source routine | Original range / use |
| --- | --- |
| `AppleS8000AESAccelerator::performAESQuantum(IOAESAcceleratorCommand*)` | `0xfffffe0009d50a28..0xfffffe0009d51168`; original entry executes from the public request path. |
| `_enableAES(bool)` | `0xfffffe0009d4f964..0xfffffe0009d4fc9c`; predicate/trace prefixes execute, with no device effects. |
| `_configureAES(IOAESAcceleratorCommand*,unsigned int)` | `0xfffffe0009d4fcf8..0xfffffe0009d5070c`; complete source captured; body unexecuted. |
| `_prepareTransfer(unsigned int,unsigned int,IODMACommand*,IODMACommand*,u64,u64,u64)` | `0xfffffe0009d51168..0xfffffe0009d513e4`; separate consumer prefixes execute. |

| Receiver / offset | Original slot | Exact target | Diversity |
| --- | --- | --- | --- |
| DMA vptr `0xfffffe0007f411f8` +0x148 | `0xfffffe0007f41340` | `0xfffffe000c528964`, `IODMACommand::setMemoryDescriptor(IOMemoryDescriptor const*,bool)` | 0x0b91 |
| Same +0x150 | `0xfffffe0007f41348` | `0xfffffe000c52887c`, `IODMACommand::clearMemoryDescriptor(bool)` | 0x9c32 |
| Same +0x178 | `0xfffffe0007f41370` | `0xfffffe000c527544`, `IODMACommand::genIOVMSegments(u64*,void*,u32*)` | 0x3968 |
| Descriptor vptr `0xfffffe0007f85d80` +0x148 | `0xfffffe0007f85ec8` | `0xfffffe000c531be4`, `IOMemoryDescriptor::performOperation(unsigned int,u64,u64)` | 0xf96b |

All four original slots are format 8, authenticated, key=0/IA and address-diversity=1. The descriptor +0x148 method is `performOperation`, distinct from the earlier `prepare(unsigned int)` at +0x218. Local SDK `IOMemoryDescriptor.h` names operation 2 as `kIOMemoryIncoherentIOStore` and operation 1 as `kIOMemoryIncoherentIOFlush`; its text requires prior preparation. Original common `performAES` issues the earlier prepare API calls in these components, but both prepare and cache effects remain modeled. SDK paths/hashes and the unmatched-build limitation are recorded. [QB4,QB8]

## Same carrier and inner job from the public entry

The public method's original pool acquisition provides common carrier C, private identity `0x6500031f00`. Original source packs, queues and dequeues it, computes a first quantum and calls candidate `performAESQuantum(provider,C)`. The driver obtains job J, `0x6500041f00`, through inner-pool `getCommand(false)`, then publishes C into J+0x30 at `0xfffffe0009d50a9c`. Its adapters remain the original source-created pair `0x6500053e00` / `0x6500053f00`.

Thus the common pool lease uses blocking mode true, while the hardware-job pool lease uses false. Both source gate/list paths execute; no new allocations occur. At the configuration frontier the common pool and inner pool each contain 31 free objects, the common provider gate remains active with packed state 0x100, the common busy byte is 1, and the pending hardware-job queue is still empty. The hardware job has not yet been enqueued for the device.

Under declared enabled bit 1, `_enableAES(true)` reads the matching bit and takes its original early return. This establishes only a source predicate outcome. The disabled-bit case instead reaches `_enableDevice(true)`, `0xfffffe0009d4f650`, and stops before its body. At that point the backlink exists but outstanding bookkeeping has not yet been incremented, because `_enableAES` has not returned.

After the already-enabled branch, original source increments provider+0x168 from 0 to 1. For the selected operation classes it then binds descriptors and performs range operations. Let A/B be carrier offsets+0x50/+0x58, P be progress+0x68 and Q be quantum+0x70. The observed selected-operation mapping is:

| Declared operation | Adapter A binding / descriptor operation | Adapter B binding / descriptor operation |
| --- | --- | --- |
| 0 | Input descriptor; code 2, offset A+P, length Q | Output descriptor; code 1, offset B+P, length Q |
| 1 | Output descriptor; code 2, offset B+P, length Q | Input descriptor; code 1, offset A+P, length Q |

Both setMemoryDescriptor calls receive Boolean true. All new request cases begin with source progress P=0. A 65536-byte request yields first quantum Q=32768 bytes. One in-place case uses the same descriptor pointer for both roles and still issues both binding/range calls. These finite operation inputs do not establish names or behavior for every driver operation.

The source does not branch on the returned registers from these two binding and two range-operation calls before `_configureAES(provider,C,0)`. Supplying declared nonzero returns 0xe00002bc for all four calls produces exactly the same original PC sequence and final object images as the matched zero-return case. This is a caller result-register observation under no-effect models; actual failing API side effects and native acceptance remain unknown. [QB2-QB4,QB8]

## Conditional configuration-error cleanup

One case substitutes return register 0xe00002bc with no effects at the configuration entry. The original caller takes its nonzero branch and requests `clearMemoryDescriptor(true)` on both adapters. It then clears J+0x30, returns J to the inner pool and decrements provider+0x168 back to zero, in this exact order:

| Ordered cleanup event | Original source |
| --- | --- |
| Clear both DMA descriptors | Calls at `0xfffffe0009d50d8c`, `0xfffffe0009d50dcc`; no-effect API models |
| Clear job backlink | Store at `0xfffffe0009d50dd0` |
| Return job through inner-pool gate/list code | Call at `0xfffffe0009d50dfc`; head store at `0xfffffe000c51fd1c` |
| Decrement outstanding bookkeeping | Store at `0xfffffe0009d50e0c` |
| Request `_enableAES(false)` | Call at `0xfffffe0009d50e1c` |
| Stop before register-base load | `0xfffffe0009d4fa50`, within the disable prefix |

At this boundary the inner pool has 32 jobs again, while the common pool still has 31 carriers and the common busy byte remains 1. Carrier status+0x78 remains zero. The enabled-state fixture bit is still 1 because the later source publication has not executed. Private trace bookkeeping executes in the extended provider reservation; it is not a measured native device state.

This case establishes the caller's conditional cleanup order, not an authentic hardware/configuration failure, completed disable, returned public status or recovered waiter/completion policy. In particular, the configuration return and carrier status are separate channels here. [QB3-QB5,QB8]

## Separate transfer-helper record consumers

These components enter `_prepareTransfer` directly with the recovered adapter pair and explicit arguments. They do not resume a public call through successful `_configureAES`. The observed input ABI is X0=provider, W1/W2=two raw control inputs, X3/X4=DMA adapters, X5/X6=offsets and X7=remaining byte count. Both raw control inputs are zero in the new cases.

For a nonzero remaining count, source initializes one-segment count=1 and separate zeroed 16-byte record slots, then calls each adapter's original +0x178 binding. Each `genIOVMSegments` interface receives this, a u64 offset pointer, record pointer and u32 count pointer. The model supplies declared little-endian u64 address/length records, cursor updates and count=1. No native mapping is generated.

Original source loads both returned records and computes an unsigned minimum:

```text
selected_count = min(remaining_count, first_segment_length, second_segment_length)
```

| Remaining count (bytes) | First length (bytes) | Second length (bytes) | Original selected count (bytes) |
| --- | --- | --- | --- |
| 32 | 64 | 16 | 16 |
| 64 | 32 | 128 | 32 |
| 16 | 32 | 64 | 16 |

These cases stop at `0xfffffe0009d5127c`, before loading the register base. No device command emitter runs. A zero remaining count takes the original empty-work return with X0=0 and no segment API call. Declared nonzero status from the first or second generator instead reaches source error-diagnostic prefixes at `0xfffffe0009d513b4` or `0xfffffe0009d51388`; execution stops before their bodies and before register access.

The record addresses are declared data values 0x100000 and 0x200000, not observed physical/bus mappings. The unsigned-minimum observation and record ABI do not establish real mapper extents, a prepared DMA object, device acceptance or cryptographic output. [QB6-QB8]

## Finite cases and verification

| Cases | Component | Verified endpoint |
| --- | --- | --- |
| 0-2 | Public requests: operation 0 / operation 1 with offsets / 65536-byte request | Source outer-carrier and inner-job handoff, adapter/range mapping, configuration entry frontier |
| 3 | Same 32-byte request with nonzero binding/cache return fixtures | Same original PC sequence and object images through configuration frontier |
| 4 | Declared nonzero configuration return | Inner-job cleanup order; stop before disable/register-base access |
| 5 | Declared disabled state | Stop before `_enableDevice(true)` body |
| 6-8 | Separate transfer consumers with declared segment records | Original minimum selection; stop before register-base access |
| 9 | Separate zero-length transfer | Original zero return without generator calls |
| 10-11 | Separate first/second generator error inputs | Error-diagnostic frontiers, no register access |
| 12 | In-place 32-byte request | Both adapters bind the same descriptor and both range operations still occur |

Fresh independent A64 replay verifies 6226 original instruction visits, 1146 writes (8955 bytes), 1432 reads (10978 bytes), 351 logical authentication steps, 202 indirect edges, 123 declared API models, 13 boundaries, 1950 final object images and 26 source-global images. Frame checks include seven original quantum entries, eight enable entries, twelve adapter bindings, twelve range operations, six configuration boundaries, six separate transfer entries and nine generator calls. Twenty-one declared segment model effects cover 196 bytes and remain separate from source writes.

All 13 initial object snapshots and final global images are checked against their source producers. The allocation-accounting and DMA metaclass snapshots remain unchanged. No new job/DMA allocation occurs. The private provider extent is explicitly enlarged to 0xa00 bytes to capture trace accesses, with no claim that native owner extents are established.

Run from the extracted directory: `PYTHONPATH=triage_evidence "$PYTHON" -P triage_evidence/validate_aes_quantum_binding.py`. Complexity is O(image bytes + source visits + journal events + objects) time and O(image bytes + journals + private RAM) space. Addresses/offsets are hexadecimal; byte counts are exact integers; one byte is 8 bits. No timing, bus bandwidth or measured cache effect is inferred.

## Bounded continuation and scoped quality gates

| Impact | Remaining evidence | Purpose |
| --- | --- | --- |
| High | Authentic `_enableDevice`/activation, register mapping and enabled-flag producer | Establishes the real prerequisite behind the no-device branch premise. |
| High | Actual caller key metadata and complete configuration semantics | Connects the current frontier to authentic configuration and subsequent submission. |
| High | Real descriptor binding, cache operations and segment producer | Establishes actual mapping/extent/readiness rather than declared API records. |
| High | Native configuration-error effects and caller completion/wait policy | Resolves the distinct return/status/resource channels beyond this partial cleanup. |
| Medium | Remaining operation classes and nonzero-progress caller epochs | Extends the selected descriptor-role/range mapping without guessing cipher-operation names. |
| Medium | Native IRQ/job completion and original constructor-to-daemon join | Connects submission/output to the established common consumer contracts. |

QG1: Descriptive technical evidence is sufficient for this increment.

QG2: QB1-QB8 enumerate premises, dependent results and falsification probes.

QG3: The increment covers public-to-inner-job identity, precise binding/cache interfaces, selected range mapping, conditional cleanup and separate segment consumers. The full daemon/kext/native investigation remains active.

QG4: Pool counts, offset/count arithmetic, u16/u32/u64 fields, record extents and replay totals are explicit and reproducible.

QG5: Prepare, performOperation, descriptor binding, configuration return, carrier status and segment records are separated. Activation, real failure effects, hardware readiness and complete return/completion policy remain explicitly unknown.

QG6: Original bytes/symbols/fixups, exact object/global transfers, separately identified SDK declarations and fresh CPU/read/write replay provide provenance. No native cache, mapper, DMA, device, crypto, Mach IPC or PAC operation executes; no IDB is changed.

QG7: The impact-labelled continuation table identifies unresolved architectural joins. Scoped gate passage does not establish authentic activation, configuration success, hardware completion or constructor/daemon continuity.

The later [DMA preparation report](aes_dma_preparation_report.md) replaces selected no-effect API premises with original-source contracts: fresh binding requests prepare(0,0,true,true), zero length derives from descriptor+0x50 through a 32 B summary, and codes 1/2 in the pinned descriptor implementation take a barrier-only path. Same-pointer binding shortcuts preparation. Segment cursor gates, callback/shim result separation and the transfer minimum are recovered; complete mapper/configuration effects and native continuity remain unknown.

## Configuration continuation

The [configuration/command report](aes_configuration_commands_report.md) resolves the source call at `0xfffffe0009d50d4c` as `_configureAES(provider,command,0)`. It partitions operation and normalized selected-key selector inputs, recovers bounded command layouts and orders software trace, cursor update and MMIO stores. Recognition is not complete later admission; hardware completion and same-job descriptor/command continuity remain unknown (AC1-AC8).

## Provider extent provenance and interrupt continuation

The [trace/wakeup report](aes_trace_wakeup_report.md) supplies class metadata and allocation-request provenance for the existing private 0xa00-byte provider reservation. It recovers startup/state/completion/command record roles, all eight literal cursor stores and the conditional configuration-wakeup producer. Source size and argument contracts do not establish actual allocator capacity, initial bytes, device completion or native request pairing (TW1-TW8).
