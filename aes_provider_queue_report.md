# AES provider packing and source queue handoff to a candidate driver

Original `IOAESAccelerator::performAES` now executes from entry through descriptor API models, original pool acquisition, carrier packing, provider-gate dispatch, queue insertion and `_startCommand` dequeue. Four declared requests reach the included AppleS8000AES `performAESQuantum` entry with the same source-leased carrier. The driver body is not executed. The candidate class, metadata, descriptor results and thread/lock outcomes remain explicit premises; this is not native driver acceptance or continuation of the original kext constructor. [PQ1-PQ8]

```text
published source pool/actors + declared nominal candidate class
  -> original hardware configuration slice
  -> original common limit calculation + action binding
performAES original entry
  -> source metadata/capability checks
  -> prepare / physical-address API models
  -> original pool get(true): carrier C
  -> source pack C
  -> provider gate -> original _queueLocked -> enqueue C
  -> original _startCommand -> dequeue C -> quantum count -> busy=1
  -> candidate performAESQuantum(provider, C) [STOP before body]
```

[Source](triage_evidence/aes_provider_queue_source.json), [profiles](triage_evidence/aes_provider_queue_profiles.json), [independent replay/oracles](triage_evidence/aes_provider_queue_checks.json), [preservation](triage_evidence/aes_provider_queue_delivery.json) and [scoped gates](triage_evidence/aes_provider_queue_quality_gates.json) retain the evidence. The external starting state is case 1 of the [source-seeded command-pool profiles](triage_evidence/aes_command_pool_profiles.json). The [actual kext constructor](kext_startup_hardware_bridge_report.md) remains at its earlier hardware-method boundary; its provider identity and opaque key data are not established by these API fixtures.

## Assumption register

| ID | Premise and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PQ1 | The pinned collection supplies the framework and included candidate driver. | Rehash it; recapture 38 complete functions and seven bindings; compare exact symbols. A different runtime build/vptr invalidates runtime application. |
| PQ2 | The published actor snapshot is specialized with the nominal AppleS8000AES vptr. Provider+0x128 and immediate-threshold +0xa8 retain zero fixture values. Complete subclass construction and runtime service identity are unknown. | Match actual registry class, allocation, constructor and these fields before asserting native reachability or capability. Co-inclusion in the collection is insufficient. |
| PQ3 | Configuration fragments enter with explicit this-registers and preceding-success assumptions. Source stores/calculations are real, but full hardware/common start is not executed. | Recover authentic predecessors and complete initialization; compare every transferred object and fragment input. |
| PQ4 | Key-data fixture metadata is word+0=128 and word+0x24=0; IV reservation is zero; operations 0/1 are declared inputs. These are not recovered kext key data. | Obtain actual caller metadata/field provenance and a matching descriptor epoch. No key-material or encryption conclusion follows from the fixtures. |
| PQ5 | Nominal descriptor prepare returns 0 and physical-address getters return declared values. Descriptor construction, backing, extent, preparation and DMA are unproved. | Match real descriptor identity/state, native API outcomes and mapped extents before applying the path to live data. |
| PQ6 | Source-produced pool/gate/carrier objects transfer between components; lock/onThread outcomes remain models. | Establish authentic constructors, references, thread identity and exclusion. No model supplies carrier packing or queue-link writes. |
| PQ7 | PAC/stripping and nominal vtables use logical decoded pointers, not hardware authentication. | Match original chain metadata and actual receiver/action authentication. Source discriminator agreement is not runtime acceptance. |
| PQ8 | Execution stops before the candidate quantum body. No hardware result, completion, constructor warm state or daemon exchange is supplied. | Establish actual driver resources/submission/result, then preserve the same caller/carrier identity through completion and the original constructor. |

## Source configuration and nominal dispatch

Collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Thirty-eight complete functions contain 3318 instructions. Seven original format-8 authenticated slots have key=0/IA and address-diversity=1. No hardware authentication is executed.

| Source component | Established output / boundary |
| --- | --- |
| AppleS8000AES start slice `0xfffffe0009d4f32c..0xfffffe0009d4f340` | Original stores give raw u64 values 33554432 at provider+0x88/+0x90 and u32 value 1 at +0xb0. No physical units are assigned to the two raw inputs. |
| Common start slice `0xfffffe000abfc4ac..0xfffffe000abfc598` | Original default/calculation yields +0xc8=2097152 and +0xe0/+0xe8=32768. The latter are byte-count limits in the carrier consumer. |
| Action slice `0xfffffe000abfc598..0xfffffe000abfc644` | Re-resolves the candidate virtual queue method and stores the generic action at provider+0xf0; existing gate/pool pointers are retained. |
| Candidate `getSupportedOptions`, `0xfffffe0009d51ad8..0xfffffe0009d51af4` | Original source reads provider+0x128; the retained zero word selects result 0x1d. Field meaning and runtime value remain unknown. |

The descriptor-address check subtracts 1 from low32(provider+0xb0) and tests the address against that mask. The source-produced value 1 gives mask 0 in these cases. The getter outcomes remain models and establish no actual physical-address or DMA property.

| Nominal candidate vptr `0xfffffe00082fd878` / offset | Original exact target |
| --- | --- |
| +0x890 | `0xfffffe000abff358`, inherited descriptor `IOAESAccelerator::performAES(...)`. |
| +0x8a0 | `0xfffffe0009d51ad8`, `AppleS8000AESAccelerator::getSupportedOptions()`. |
| +0x8a8 | `0xfffffe0009d50a28`, `AppleS8000AESAccelerator::performAESQuantum(IOAESAcceleratorCommand*)`; frontier only. |
| +0x8d0 | `0xfffffe000abfd2d8`, inherited `_queueLocked(IOAESAcceleratorCommand*)`. |
| +0x8d8 | `0xfffffe000abfd4bc`, inherited `_startCommand()`. |
| Descriptor vptr `0xfffffe0007f85d80` +0x218 | `0xfffffe000c5353b4`, `IOGeneralMemoryDescriptor::prepare(unsigned int)`; result model. |
| Import slot `0xfffffe000858a620` | `0xfffffe000c53c2c4`, `IOMemoryDescriptor::getPhysicalAddress()`; result model. |

The candidate quantum slot carries original diversity 0xa913, matching the framework's virtual call. The inherited descriptor API and queue methods provide a source interface from the common family to this included hardware class; they do not prove that service matching returned that class in the historical RAX or kext epoch.

## Same carrier across pool, packing and active queue

The source pool provides its most recently seeded carrier, private identity `0x6500031f00`, in each request. Pool acquisition clears both link words. Original `performAES` fills that same object, then the provider gate invokes original `_queueLocked(provider, carrier, 0, 0, 0)`. With the retained zero immediate threshold and nonzero request length, source takes the queued path.

| Ordered source event | Exact writer |
| --- | --- |
| Pool removes carrier and clears +0x10/+0x18 | `0xfffffe000c51fe50` |
| Packing starts with input/output descriptors at +0x20/+0x28 | `0xfffffe000abff7f8` |
| Active queue writes its link pair at +0x10/+0x18 | `0xfffffe000abfd374` |
| `_startCommand` removes the carrier and clears the same links | `0xfffffe000abfd550` |
| Current quantum byte count stored at +0x70 | `0xfffffe000abfd554` |
| Provider busy byte +0x110 stored as 1 | `0xfffffe000abfd55c` |

These six instruction epochs have strict order in every request. Each paired clear is observed as two 8 B memory events from one original paired-store instruction. Sixteen individual cleared link words are checked. Pool and active queue reuse the same carrier link fields; they are not different nodes or copied records.

At the driver entry, 31 carriers remain in the pool. The provider queue's head/tail both equal its sentinel provider+0x100, because `_startCommand` has already dequeued the active carrier. Provider busy=1, provider-gate packed state=0x100 and pool-gate state=0. The current carrier is conveyed in X1 to the virtual method. These are source/private-state facts, not native lock or ownership guarantees.

## Carrier fields and byte-count transfer

| Carrier offset | Width | Source-produced value at the driver frontier |
| --- | --- | --- |
| +0x20 / +0x28 | 8 each | Input/output descriptor pointers, identical or distinct according to the declared request. |
| +0x30 / +0x38 | 8 each | Total request length / original IV pointer. |
| +0x40 | 4 | Original low32 operation, 0 or 1 in these cases. |
| +0x48 | 8 | Original opaque key-data pointer. |
| +0x50 / +0x58 | 8 each | Two original offset values, preserved at full width; downstream interpretation remains unexecuted. |
| +0x60 | 8 | Source-selected per-operation byte-count limit, 32768 in the retained configuration. |
| +0x68 | 8 | Initial progress value 0. |
| +0x70 | 8 | Current quantum count: unsigned min(total-progress, limit). |
| +0x80 / +0x88 | 8 each | Original completion function/context pointers, including the declared non-NULL pair. |

For the 65536 B request, `remaining = 65536 B - 0 B = 65536 B`, hence `quantum = min(65536 B,32768 B) = 32768 B`. The 16/32/64 B requests each use their full length for the first quantum. No later progress increment, second quantum or completion is executed.

The completion-status area at +0x78 is not assigned a result by this prefix. Its retained zero bytes come from the earlier modeled carrier construction; they are not an AES success result. The callback/context case verifies pointer forwarding, not asynchronous invocation or completion semantics.

Both descriptor roles request `prepare(0)` and physical-address lookup, even when their pointers are identical. The physical-address model returns 0x100000 for the input fixture and 0x200000 for the separate output fixture. These are declared numbers, not observed physical mappings. No payload buffer is accessed by these models.

The original prefix reads only two 4 B words from the declared key-data reservation, at offsets 0 and +0x24; it stores the opaque pointer in the carrier. It does not read IV bytes before the driver entry. No actual kext key-data bytes, key material, IV consumption, ciphertext/plaintext or cryptographic result is established. [PQ4, PQ5, PQ8]

## Independent checks and reproduction

| Case | Source visits | Result/frontier |
| --- | --- | --- |
| Hardware configuration slice | 5 | Three raw provider fields source-written. |
| Common limit calculation | 102 | Default ceiling 2097152 and quantum limits 32768. |
| Candidate action binding | 21 | Original virtual resolution and provider+0xf0 store. |
| Same descriptor, length 32 B, operation 0 | 507 | Candidate quantum entry, current count 32 B. |
| Separate descriptors, length 64 B, operation 1, offsets 16/32 | 507 | Same carrier identity; original offsets and descriptor pointers preserved. |
| Same descriptor, length 16 B, non-NULL completion/context | 507 | Pointer forwarding; callback not executed. |
| Same descriptor, length 65536 B, operation 0 | 507 | First quantum 32768 B; driver body unexecuted. |

Seven independent fresh replays verify 2156 original visits, 461 reads / 3508 B, 359 writes / 2808 B, 68 logical indirect edges and 108 logical authentication/stripping steps. Four pool-action frames/statuses, four original queue-action entries and four candidate quantum frontiers pass. All 343 final object images and six intra-increment source-produced object transfers pass. Thirty-six API models cover eight prepare requests, eight address requests, eight close-gate requests, eight onThread results and four open-gate requests. No model writes memory in this increment; source instructions produce all carrier and queue effects after the declared initial fixtures.

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_aes_provider_queue.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_aes_provider_queue.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_aes_provider_queue.py
```

Run producers sequentially in a separate evidence-tree copy for reproduction; published artifacts remain preserved. Complexity is O(image bytes + symbols + visits + effects + carrier checks) time and O(image + retained journals + fixed private RAM) space. Original source words, each read/write, model arguments/clobbers, logical authentication/branch records, final RAM and driver frames are independently replayed. Original inputs, IDBs and memory files remain unchanged. No target daemon, native Mach, descriptor/DMA, lock/thread, hardware AES or hardware PAC operation is executed.

## Bounded continuation and quality gates

| Impact | Remaining question | Resolving evidence |
| --- | --- | --- |
| High | The nominal candidate has not been identified as the runtime service. | Match registry class/build/vptr and authentic complete subclass initialization before applying this path natively. |
| High | The actual kext constructor's metadata/descriptors remain unjoined to this ordinary API component. | Transfer authentic caller state and opaque metadata provenance without substituting fixture values or a successful AES result. |
| High | Driver submission, DMA/resources, completion and subsequent quanta remain unexecuted. | Recover authentic resources and one complete same-carrier lifecycle; distinguish source interfaces from hardware effects. |
| Medium | Immediate, busy/concurrent queue and teardown branches remain untested. | Establish their actual configuration/predecessors and exclusion/reference contracts. |
| Medium | Capability word +0x128 and raw sizing inputs have no established runtime values or complete semantic names. | Recover their preceding writers and hardware/build context; fixture zero is not runtime attestation. |
| Low | Pool links are reused by the active queue. | Preserve one carrier identity and the clear/insert/remove ordering in later lifts and completion analysis. |

- QG1: Factual source/ABI analysis; no normative conclusion required.
- QG2: PQ1-PQ8 identify premises, dependent results and falsification probes.
- QG3: Source configuration, original performAES packing, same-carrier pool/queue transfer and candidate quantum ABI are covered. Native construction/hardware/constructor/daemon continuity and the full objective remain incomplete.
- QG4: Raw input values versus byte-count consumers, 32/64-bit fields, offset forwarding and the quantum calculation are explicit; no native timing, capacity or cryptographic result is inferred.
- QG5: Class adaptation, source fragments, declared metadata/descriptors, source/model/native effects, status bytes and driver-entry/body execution remain distinct.
- QG6: Pinned functions/slots, source producer stores, independent CPU/effect replay and separate carrier/order/metadata/quantum oracles support the scoped claims.
- QG7: Additional questions are bounded and impact-labeled above.
