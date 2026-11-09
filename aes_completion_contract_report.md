# AES completion interfaces: candidate interrupt, hardware job and common carrier

The matching collection contains a static route from the included AppleS8000AES interrupt handler through its hardware-job queue to `IOAESAccelerator::completeAESQuantum`. The hardware job and common command carrier occupy different pools. Five conditional CPU cases establish the common consumer's admission, requeue, callback and wakeup contracts. Hardware submission/completion, actual status generation, cryptographic output, native synchronization and resumption of the FairPlayIOKit constructor remain unknown. [CC1-CC8]

```text
Original source, static only:
 candidate performAESQuantum(provider, carrier C)
   -> inner pool -> hardware job J; J+0x30 = C
 device IRQ bit 5 -> candidate _completeAES()
   -> tag/pending-job processing -> save C -> clear J backlink
   -> return J to inner pool -> completeAESQuantum(provider, C)

Conditional CPU consumer cases, declared event/status inputs:
 completeAESQuantum(provider, C)
   -> busy=0 -> progress += quantum
   +-> progress < total AND status == 0 -> requeue C -> start quantum
   `-> otherwise -> descriptor complete(0) for each role
         +-> callback present: return C to outer pool -> callback(ctx,status)
         `-> callback absent: commandWakeup(gate,C,false) [STOP before callee]
```

[Original source and slots](triage_evidence/aes_completion_contract_source.json), [conditional profiles](triage_evidence/aes_completion_contract_profiles.json), [independent replay and contract checks](triage_evidence/aes_completion_contract_checks.json), [preservation](triage_evidence/aes_completion_contract_delivery.json) and [scoped gates](triage_evidence/aes_completion_contract_quality_gates.json) are the reproducible evidence. Earlier [provider packing/queue](aes_provider_queue_report.md) and [pool construction](aes_command_pool_report.md) supply the source-produced actor/carrier snapshots. These are explicit private states, rather than an observed live device epoch.

## Assumption register

| ID | Premise and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CC1 | The pinned collection supplies the common framework and included candidate driver. Static facts apply to these bytes. | Rehash the collection and recapture 43 functions, 4256 instructions, six origin sites and four authenticated slots. A different runtime image requires remapping. |
| CC2 | The actor has the declared candidate vptr and earlier source-produced gate/pool state. Actual service identity and complete subclass construction are unknown. | Recover authentic construction and registry matching, then compare receiver class, resources and object fields before applying the path to a native instance. |
| CC3 | Admission substitutes an arbitrary return-register sentinel at candidate submission; no device result or memory effect is supplied. | Execute the authentic submission with established resources. The current original caller returning zero establishes one conditional admission path, not universal hardware behavior. |
| CC4 | Completion enters directly with a declared u32 status at carrier+0x78. The producer, device epoch and authentic status value are unknown. | Find every alias/helper writer and connect the actual interrupt/job/carrier epoch. Consumer acceptance of an injected zero is insufficient. |
| CC5 | Descriptor prepare/address/complete and callback operations are no-effect API models; metadata and backing are declared fixtures. | Establish native descriptor identity, preparation pairing, extent, DMA/output and real callback behavior. No native data completion follows from model return zero. |
| CC6 | Object snapshots transfer exactly between components; onThread/lock operations remain declared outcomes. A NULL-callback case is a separate event component. | Preserve native thread, gate, exclusion and waiter identity through an authentic event. This increment does not execute sleep, wakeup or waiter resumption. |
| CC7 | PAC and chained pointers are represented logically. | Compare original format-8 slot metadata and actual receiver/function authentication. No hardware PAC acceptance is claimed. |
| CC8 | Selected source interfaces are bounded; full driver construction, status origins and constructor/daemon continuation are outside the verified component. | Recover missing constructors, job adapter types, event producers and end-to-end ownership before claiming a completed FairPlayIOKit/fairplayd transaction. |

## Original identity and dispatch

Primary input: `/Users/___/Downloads/fpx/img4_dump/kernelcache.macho`, SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Exact nlist names, compiler function boundaries, instruction bytes and original chained-pointer records are retained in the source JSON. No IDA labels or inferred C return types serve as primary evidence. The five added complete functions are:

| Component / routine | Entry | Exclusive end |
| --- | --- | --- |
| IOCryptoAcceleratorFamily `IOAESAccelerator::completeAESQuantum(IOAESAcceleratorCommand*)` | `0xfffffe000abfd174` | `0xfffffe000abfd270` |
| IOCryptoAcceleratorFamily `IOAESAccelerator::_completeAES(IOAESAcceleratorCommand*)` | `0xfffffe000abfd598` | `0xfffffe000abfd6f8` |
| AppleS8000AES `AppleS8000AESAccelerator::performAESQuantum(IOAESAcceleratorCommand*)` | `0xfffffe0009d50a28` | `0xfffffe0009d51168` |
| AppleS8000AES `AppleS8000AESAccelerator::_completeAES()` | `0xfffffe0009d5153c` | `0xfffffe0009d51950` |
| AppleS8000AES `AppleS8000AESAccelerator::_interruptOccurred(IOInterruptEventSource*,int)` | `0xfffffe0009d4f558` | `0xfffffe0009d4f650` |

The two `_completeAES` routines are different signatures and targets. The candidate's inherited virtual +0x8e0 resolves to the common carrier finalizer; the interrupt handler branches directly to the candidate's no-argument routine.

| Receiver / virtual offset | Original slot | Decoded target | Diversity |
| --- | --- | --- | --- |
| Candidate vptr `0xfffffe00082fd878`, +0x8b0 | `0xfffffe00082fe128` | common `completeAESQuantum`, `0xfffffe000abfd174` | 0xeb83 |
| Same vptr, +0x8e0 | `0xfffffe00082fe158` | common carrier `_completeAES`, `0xfffffe000abfd598` | 0x3cca |
| Descriptor vptr `0xfffffe0007f85d80`, +0x220 | `0xfffffe0007f85fa0` | `IOGeneralMemoryDescriptor::complete(unsigned int)`, `0xfffffe000c534a2c` | 0x9285 |
| Gate vptr `0xfffffe0007f3fbb0`, +0x208 | `0xfffffe0007f3fdb8` | `IOCommandGate::commandWakeup(void*,bool)`, `0xfffffe000c51e19c` | 0xf36c |

All four records are format 8, auth=1, key=0/IA and address-diversity=1. Runtime authentication remains untested. [CC1,CC2,CC7]

## Static hardware-job adapter and interrupt route

At `0xfffffe0009d50a68`, candidate submission loads an inner pool from provider+0x158, requests `getCommand(false)` and tests its result. At `0xfffffe0009d50a9c`, original code publishes the supplied outer carrier into job+0x30. That backlink permits completion to recover the original common carrier. The hardware method body is captured statically; it is not executed by these profiles.

| State | Original use and established width |
| --- | --- |
| Provider+0x140/+0x148 | Pending hardware-job queue head/tail, pointer words. |
| Provider+0x158 | Inner hardware-job pool pointer; distinct from common provider+0xf8 carrier pool. |
| Job+0x20/+0x28 | Two adapter pointers required non-NULL by candidate completion. Exact dynamic types remain unknown. |
| Job+0x30 | Outer common carrier backlink, 64-bit pointer. |
| Job+0x38 | 16-bit job tag; completion copies it to provider+0x164 as u32, then stores 0xffff back into the job tag. |
| Provider+0x168 | 32-bit outstanding bookkeeping, checked nonzero before decrement. |
| Provider+0x178 | Register-base pointer used by interrupt and completion source. Physical mapping/construction is unknown. |

The interrupt source first tests provider+0x1f8 bit 0. It reads a u32 register at base+0x18 (`0xfffffe0009d4f580`) and writes the same word back (`0xfffffe0009d4f584`); this is a source read/write pattern with no observed hardware acknowledgment effect. It selects an error mask using provider+0x128 and branches to an error path if selected bits are set. Bit 0 controls a separate base+0x1c update and possible gate wakeup with event provider+0x150. Bit 5 selects the tail branch at `0xfffffe0009d4f628` to candidate `_completeAES()`.

Candidate `_completeAES()` polls register base+0x30 until bits 8..15 are zero, then extracts bits 0..7. It compares tag state and walks the pending hardware-job queue. For each selected job, it unlinks and clears the job links, loads adapters and the carrier backlink, performs operation-dependent adapter work, clears the backlink, returns the job and calls the common completion interface:

| Ordered adapter event | Exact source PC |
| --- | --- |
| Load outer carrier from job+0x30 into X22 | `0xfffffe0009d516bc` |
| Clear job+0x30 | `0xfffffe0009d51784` |
| Return job to provider+0x158 pool | `0xfffffe0009d51808` |
| Decrement provider+0x168 | `0xfffffe0009d51818` |
| Call virtual +0x8b0 with provider and saved carrier | `0xfffffe0009d51844` |

Thus the inner job can be recycled before the common carrier is completed. The IRQ register word, hardware tag word and common carrier+0x78 status are distinct channels. The selected driver functions do not establish the authentic producer of carrier+0x78; helper/alias writers have not been exhaustively recovered. Neither register bits nor injected status are evidence of an actual hardware result. [CC2,CC4,CC8]

## Common completion algorithm and ownership

Original `completeAESQuantum` clears provider busy at `0xfffffe000abfd18c`. It reads u64 progress and quantum from carrier+0x68/+0x70, adds them and stores the result at `0xfffffe000abfd1a0`, before reading u32 status+0x78. It finalizes if updated progress is unsigned-greater-or-equal to total+0x30, or if progress remains below total and status is nonzero. Otherwise it requeues that same carrier and starts another quantum.

```text
busy = 0
progress = (progress + quantum) mod 2^64
if progress >= total OR status_u32 != 0:
    finalize(carrier)
else:
    enqueue_tail(carrier)
start_next_command()
```

This is a bounded source summary: queue-integrity checks, PAC checks and external callees remain in the captured code. The total comparison short-circuits the status test. The addition is bookkeeping even in a nonzero-status case; it does not measure successfully encrypted bytes. The finite fixtures use 32, 32768 and 65536 bytes, with no overflow. General overflow reachability remains unknown.

Common `_completeAES(carrier)` calls `complete(0)` for the input descriptor at `0xfffffe000abfd5e4` and output descriptor at `0xfffffe000abfd624`. Both calls occur even when the two role pointers are identical. Real descriptor bookkeeping and call results remain outside the CPU model.

For a non-NULL callback, source loads status as W21 (zero-extended to X21), loads context into X22 and saves the callback on the stack. It then returns the carrier to the outer pool at `0xfffffe000abfd664`, and tail-calls the saved callback with X0=context and X1=zero_extend64(status_u32), using discriminator 0xd507 at `0xfffffe000abfd698`. The cached callback/context/status survive source pool return. The callback must not infer that this carrier remains exclusively leased from its former submission. Real callback code/reentrancy is unknown.

For a NULL callback, it tail-calls `commandWakeup(provider_gate, carrier, false)` at `0xfffffe000abfd6f4`. This branch does not return the carrier to the outer pool. The earlier queue/waiter source supplies a later reclamation path; the present case stops before wakeup and establishes no resumed waiter or completed synchronous submission. [CC4-CC7]

## Five independently replayed conditional cases

The admission case starts from published provider configuration/binding. Event cases transfer the preceding source-produced object state, then explicitly inject u32 status and enter common `completeAESQuantum` on a declared caller stack. The NULL-callback case uses the earlier in-flight 32-byte request state. These entries do not assert one native scheduler epoch.

| Case | Declared premise | Source outcome | Final outer pool |
| --- | --- | --- | --- |
| 0, admission | 65536-byte request, callback present; candidate submission returns arbitrary X0=0x1122334455667788 with no effects | Public `performAES` returns X0=0; progress=0, quantum=32768, busy=1; provider gate state restored | 31 carriers |
| 1, partial event | Case 0 state; status=0 | Progress=32768; same carrier requeued/dequeued; next quantum=32768, busy=1; stop before driver body | 31 carriers |
| 2, nonzero event | Case 0 state; status=0xe00002bc | Progress=32768; both descriptor roles completed through models; source pool return precedes callback(context,0xe00002bc); busy=0 | 32 carriers |
| 3, total event | Case 1 state; status=0 | Progress=65536; both descriptor roles completed through models; source pool return precedes callback(context,0); busy=0 | 32 carriers |
| 4, NULL-callback event | Earlier 32-byte in-flight state; status=0xe00002bc | Progress=32; two role completion models; stop before wakeup(gate,carrier,false) | 31 carriers |

Zero callback status in case 3 is a declared event input. It is not an AES success claim. The common completion return register in cases 2/3 contains the provider pointer after its continuation, rather than a returned status code. Case 0's ignored submission register and public zero likewise establish separate admission/result channels only under the declared premises.

Fresh independent A64 replay checks 1220 original instruction visits, 181 source writes (1398 bytes), 311 reads (2398 bytes), 78 logical authentication steps, 46 indirect edges, 25 no-effect API models, five boundaries and 245 final object images. Separate oracles check all five object transfers, linked-list ownership/counts, status fixtures, progress-before-status ordering, two saved callbacks after pool return, partial requeue and the NULL-callback wakeup frontier. These are finite reproducibility checks with explicit model premises, rather than exhaustive behavior or native validation.

Reproduce from the extracted directory with `PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_aes_completion_contract.py`. Source capture/probe/replay/check algorithms use time O(image bytes + instruction visits + journal events + carriers) and space O(image bytes + journals + private RAM). Counts and extents are exact integers; offsets/addresses are hexadecimal. Byte counts use the byte unit (8 bits); no duration, bandwidth or physical-register units are inferred.

## Bounded continuation and scoped quality gates

| Impact | Next evidence | What it resolves |
| --- | --- | --- |
| High | Recover authentic carrier+0x78 initialization and all status writers, including helper/alias stores | Connects hardware/job completion to the actual callback/synchronous result. |
| High | Recover inner job/adapter constructors and provider register mapping with exact class/vptr provenance | Establishes actual resource types and whether this candidate can supply the previously bounded kext provider. |
| High | Join original NULL-callback waiter, wakeup and reclamation with one authentic command epoch | Determines when synchronous `performAES` and the FairPlayIOKit constructor can continue. |
| Medium | Recover real callback implementations and their reference/ownership contract | Explains permitted work after the carrier has returned to its pool. |
| Medium | Recover tag wrap/reset and pending-job ownership across interrupts | Tests correspondence between low-eight-bit device tags, u16 job tags and u32 provider state. |
| Low | Extend partial/total/error finite coverage to varied valid lengths and multiple queued carriers | Exercises additional source scheduling cases without establishing hardware execution. |

QG1: This component requires descriptive technical evidence only.

QG2: CC1-CC8 enumerate premises, dependent results and falsification probes.

QG3: The increment covers static interrupt/job/common interfaces, conditional admission/completion ABI and ownership. Original port/daemon and broad investigation reports remain linked; the broad goal remains active.

QG4: Address widths, unsigned arithmetic, u32 status extension, byte extents and finite-case counts are explicit and reproducible.

QG5: Separate hardware/common overloads, separate pools, admission/status channels, source/modeled effects and NULL-callback frontier resolve the local interpretation edges. Status origins, overflow reachability and native scheduling are explicitly unknown.

QG6: Original bytes, exact symbols, chained slots, source snapshots and fresh replay provide provenance. No native IRQ, device, descriptor, callback, PAC, Mach exchange or IDB mutation occurs.

QG7: The bounded continuation table identifies remaining architectural joins and their impact. Scoped gate passage does not establish complete recovery of FairPlayIOKit/fairplayd or successful hardware cryptography.
