# Daemon cached write-lock gate before FairPlayIOKit discovery

Two obfuscated helpers immediately precede the class-selection call. In the selected caller phase, `0x10041859c` fetches a process-global cached pointer, invoking a one-time initializer on the cold path. `0x100412a78` requests `pthread_rwlock_wrlock` on a nonnull pointer and writes private status `0x8b3dc651` regardless of the returned lock status. A null pointer writes `0x74c29d88` and bypasses discovery. The original predecessor supplies the caller's expected word `0x8b3dc651`. The nonnull continuation reaches the established class-selection routine at `0x1004382b4` through the original call at `0x100636dfc`. [Original-byte audit](triage_evidence/audit_daemon_class_lock_gate.py) [Receipt](triage_evidence/daemon_class_lock_gate_audit.json.zst) [Class-selection caller](daemon_selector26_class_caller_report.md)

```text
0x10063990c  conditional entry into the helper pair
  |
  +-- 0x10047e054 -> cached lock getter -> P+0, u64
  |     cold -> dispatch_once -> malloc(200 B) -> rwlock_init
  |     warm -> read the existing cached pointer
  |
  +-- caller forwards the pointer to P+8, u64
  |
  +-- 0x10047e0f4 -> lock wrapper -> P+4, u32
  |     NULL    -> 0x74c29d88
  |     nonnull -> rwlock_wrlock(pointer) -> 0x8b3dc651
  |
  +-- 0x10047e100  compare P+4 with W22 = 0x8b3dc651
        match -> 0x100636dfc -> 0x1004382b4
        miss  -> 0x1006340c8
```

## Reaching state and private record

The producer at `0x100559b7c` establishes the frame used for the bank checks. With S denoting its post-prologue SP, FP=S+0xcc0 B and P=FP−0xa0 B. The producer loads the second helper's two byte-table bases into X16 and X15 at `0x100559c3c` and `0x100559c58`. The separate original stack writer at `0x100530454` and `0x100530458` saves that pair. The replay composes the producer, writer, and consumer as distinct source intervals on the same private frame. A continuous execution between those intervals remains unknown. [Audit](triage_evidence/audit_daemon_class_lock_gate.py)

| Caller transfer | Stack slots, table bases | Key and selected original fixup | Target |
| --- | --- | --- | --- |
| `0x10047e054` | S+0x2d0 B → `0x100fc4230`, S+0x2c8 B → `0x101031fa0` | `0x6c` → `0x87`, slot `0x1010a0df8`, IA `0xb228` | `0x10041859c` |
| `0x10047e0f4` | S+0x290 B → `0x100fc4130`, S+0x288 B → `0x101031ea0` | `0xa3` → `0x72`, slot `0x1010a15d8`, IA `0xd7e3` | `0x100412a78` |

The first bank pair is written at `0x10053045c` and `0x100530460`. Each bank equation evaluates all 256 input bytes. Under incoming W9=`0x65a1` and X7=`0x101039ef0`, `0x100639894` computes W20=`0x219a` and sets W22=`0x8b3dc651`. A nonzero X19 with incoming W11 different from that marker selects index `0x65b3` and `0x10047df94`. Either a zero X19 or a matching W11 selects index `0x65a1` and `0x1004c620c`. The incoming X19 object and W11 producer are unknown. The comparison concerns the full 32 bits of W11. [Audit receipt](triage_evidence/daemon_class_lock_gate_audit.json.zst)

| Field | Producer → consumer | Meaning in this phase |
| --- | --- | --- |
| P+8 B, u32 | `0x10047dff4` → `0x100418748` | First helper's address-dependent encoding, decoding to `0x5ca8`. |
| P+0 B, u64 | `0x10008730c` → `0x10047e058` | Cached pointer copied to caller record. |
| P+0 B, u32 | `0x10047e098` → `0x100412bdc` | Second helper's address-dependent encoding, decoding to `0xc491`. |
| P+8 B, u64 | `0x10047e09c` → `0x100412be4` | The same pointer, now the second helper's operand. |
| P+4 B, u32 | `0x10003cdbc` → `0x10047e0fc` | Wrapper status, consumed by the compare at `0x10047e100`. |

The first codec combines its address term and `W20 + 0x3b0e` with XOR. The second subtracts its address term times `0xba209ef7` from `W20 + 0xa2f7`, and the callee adds the same product. Original-instruction bit-vector proofs verify equality of each address term across all 8 B-aligned low-32-bit address projections, plus the two phase cancellations. Projections 2 and 4 B respectively break the first and second address-term equalities. The codecs require O(1) time and space per record, and exhaustive bank verification uses O(256) time and O(1) extra space per bank pair. [Codec proof](triage_evidence/daemon_class_lock_gate_audit.json.zst)

## Initialization, publication, and use

| Source site | Original call or operation | Contract in the selected phase |
| --- | --- | --- |
| `0x100418770` | Compare once word at `0x1010c67e0` with all ones | Cold branch `0x10002c110` or completed-once branch `0x1000e6cb8`. |
| `0x10002c18c` | `dispatch_once`, IA `0x6007` | X0=`0x1010c67e0`, X1=global block `0x101039c10`, whose authenticated invoke is `0x1004116b4`. |
| `0x100411954` | Call `0x10044db3c`, IA `0x2df6` | Callback passes a private record containing cache-cell address `0x1010c6820`. |
| `0x1003010ec` | `malloc`, IA `0x6aa4` | X0=200 B. NULL returns without initializing a lock. |
| `0x1003184c8` | `pthread_rwlock_init`, IA `0xa027` | X0 is the allocation base, X1 is NULL. |
| `0x10030a254` | Pointer publication | Successful initialization stores the allocation base into `0x1010c6820`. |
| `0x100254368` | `free` | With modeled init result 22, retires the allocation before getter return. The pointer stays unpublished. |
| `0x100087308` → `0x10008730c` | Cache load and output store | Both once paths load `0x1010c6820` and write P+0 B as a u64. |
| `0x10019eed0` | `pthread_rwlock_wrlock`, IA `0x4c4d` | X0 is that exact pointer. From the ordinary return through `0x10003cdbc`, instructions select the writer by the retained phase and assign constant `0x8b3dc651` independently of W0. |

The once word and cache cell are both zero in the mapped image before the modeled calls. The model treats allocation, initialization, retirement, lock acquisition and once completion as declared boundary outcomes. The callback body and the cache store execute from the original image bytes. [Evidence receipt](triage_evidence/daemon_class_lock_gate_audit.json.zst)

| Profile | Once / cache outcome | Private status at P+4 B | Last verified source boundary |
| --- | --- | --- | --- |
| Cold, allocation and initialization succeed, lock result 0 | Completed / published | `0x8b3dc651` | `0x1004382b4` |
| Warm on the same cache, lock result 5 | Completed / same pointer | `0x8b3dc651` | `0x1004382b4` |
| Cold, allocation returns NULL | Completed / NULL | `0x74c29d88` | `0x1006340c8` |
| Warm after allocation returned NULL | Completed / NULL | `0x74c29d88` | `0x1006340c8` |
| Cold, initialization returns 22 | Completed / NULL, `free` requested | `0x74c29d88` | `0x1006340c8` |
| Predecessor has NULL X19 or matching W11 (two controls) | No getter invocation | No write | `0x1004c620c` |

## IPC attribution and next evidence

The archived RAX trace independently supplies class-match 2881/2981, iterator-next 2802/2902 and type-0 open 2862/2962. The open reply declares a null connection and application result `0xe00002c2`. Guest deallocations then use service name `0x1903` and iterator name `0x1803`. The recorded trap PC is `0x180547c20`. No matching daemon caller PC, lock identity, or once-token observation accompanies the exchange. The lock helpers establish a local dependency in one source-reachable class-discovery route. They add no directly observed Mach right, emission, or selector to the capture. [Archived trace and port retirement](archived_iokit_open_retirement_report.md) [Established discovery and release continuation](daemon_selector26_class_retry_report.md)

| Open question | Impact | Evidence that would resolve it |
| --- | --- | --- |
| Where X19, W9, and W11 originate for this predecessor | High | Continuous original-source state from the outer entry into `0x100639894`, including the branch that reaches that fragment. |
| Which continuation releases the cached write lock | High | Match a subsequent unlock argument to the same pointer and process epoch, including class-open and class-skip returns. |
| Whether the archived request follows this gate | High | Same-run daemon caller PC at open and private pointer/marker evidence at the gate. |
| Whether other callers reuse the cached lock | Medium | Reconstruct the reaching phase and pointer operand for each additional accessor or unlock site. |

## Assumptions and verification

| Assumption | Dependent claim | Stress test |
| --- | --- | --- |
| A1. Pinned arm64e image and logical fixup model. | All source addresses, decoded targets, and import names. | Check original format-12 words and target/diversity for each observed authenticated transfer. PAC validity on hardware remains unknown. |
| A2. The producer and stack writer reach the consumer in the recorded frame. | Local helper pair and class-entry composition. | Replay both original writers, verify all seven relevant stack cells, and test predecessor X19 and marker alternatives. The continuous origin is open. |
| A3. P is 8 B aligned and W20 is `0x219a`. | Both decoded helper phases. | Prove source-term equality and phase cancellation, then test the two misaligned projections. |
| A4. Declared ordinary ABI returns, including modeled once completion. | Cache publication, failure retirement and lock-result controls. | Verify ordered call arguments, apply caller-saved clobbers, reuse the initial case's actual cache on the warm case, and test both allocation and initialization failure. No native allocation, release or locking is established. |
| A5. The archive supplies observation at the trap boundary. | Capture comparison only. | Rehash and decode the exact request/reply and deallocations. The native gate-to-capture join remains unknown. |

Reproduce with `python3 -B triage_evidence/audit_daemon_class_lock_gate.py` using Capstone, Unicorn and Z3. The verifier checks seven isolated profiles, both 256-input bank equations and six bit-vector queries. SHA-256 of the original `fairplayd.arm64e` is `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. [Audit generator](triage_evidence/audit_daemon_class_lock_gate.py) [Compressed receipt](triage_evidence/daemon_class_lock_gate_audit.json.zst)
