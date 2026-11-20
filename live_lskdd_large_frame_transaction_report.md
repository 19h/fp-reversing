# lskdd large-frame transaction lifecycle

The installed arm64e image's large-frame initializer calls a helper that acquires a write lock, creates or refreshes an OS transaction, increments a 32-bit counter, and unlocks. The transaction pointer, counter, and lock occupy distinct globals. The two offline cases return to the large initializer and follow the same continuation to its epilogue. The connection origin for selector 19 remains unknown. [Selector 19 frame and method](live_lskdd_selector19_binding_report.md)

## State and call sites

| State | Address | Recovered behavior |
| --- | --- | --- |
| Write lock | `0x100e80730` | X0 at the lock import transfer `0x100325284` and the unlock import transfer `0x100323220`. |
| Transaction pointer | `0x100e83798` | Stores X0 from `os_transaction_create` at `0x10017f994`. Loads X0 for `os_transaction_needs_more_time` at `0x10012a16c`. |
| 32-bit counter | `0x100e837c0` | Reads at `0x10033c4a8` select the helper branch. The common continuation reads, increments and stores at `0x100137abc`–`0x100137ac4`. |
| Selector 18 connection name | `0x100e82af8` | Established independently as the output cell for the type-zero `IOServiceOpen` and the name consumed by selector 18. [Selector 18 connection](live_lskdd_selector18_connection_report.md) |

The large-frame call at `0x1005b3c5c` resolves to `0x10033c1f4` via fixup slot `0x100e73a78`, discriminator `0x91e6`. The helper calls the lock wrapper at `0x10033c460`. Its split at `0x10033c534` uses discriminator `0xc309` for both selected targets. With the fixture's decoded helper state `0x39bf`, a zero counter selects table index `0x39d8`, slot `0x100e49cf0`, and target `0x10017f8f4`. A nonzero counter selects `0x39bf`, slot `0x100e49c28`, and target `0x10012a130`. The create import receives the literal `com.apple.daemon.lskd` at `0x100c7bda4`.

| Initial state | Imported operation | Common result |
| --- | --- | --- |
| Counter 0, transaction null | `os_transaction_create` at `0x10017f990` | Stores the returned pointer, counter 1, unlock. |
| Counter 1, existing transaction pointer | `os_transaction_needs_more_time` at `0x10012a184` | Passes the existing pointer in X0, counter 2, unlock. |

Both cases reach `0x100137abc` through their `0x5d4b` branches. The continuation resolves the unlock wrapper through slot `0x100e736f0`; its tail binds `pthread_rwlock_unlock` through `0x100e73e30`. The counter's scope beyond this acquisition path, the transaction's release sites, and the upstream caller that supplies the native context are unknown.

## Continuation and IPC boundary

The tested initializer begins after the compiler's stack probe at `0x1005b38b8`. It decodes the context word at +0x28 B by subtracting an address-derived 32-bit residue. It produces W21 = `0x45b9` in both cases, writes it to SP+0x5b94 at `0x1005c1ef4`, and takes the `0x8d35` edge to `0x100a3f46c`. The fixture subsequently writes `0x2edf880f` to context +0x2c B at `0x100aff464` and reaches the epilogue at `0x100aff4b0`. The status word's caller-visible meaning is unknown.

The previously identified selector 19 predecessor `0x100b5c91c` reads SP+0x5b94 and would require state `0x45a7` for its indexed edge into the method block. Simply using `0x45a7` as the initial decoded W21 on the zero-counter fixture produces index `0x39ca` at `0x10033c4dc`. That slot has discriminator `0x02ed`, whereas the branch requires `0xc309`. This result distinguishes the candidate predecessor's required word from the earlier initializer state on the tested path.

The audited calls belong to libSystem. The two offline cases reached neither `IOServiceOpen` nor the selector 19 method. For an ordinary selector 19 inline emission, the known framework send site is `0x184ebe090`, request/reply IDs are 2865/2965, and the rights are COPY_SEND to the connection and MAKE_SEND_ONCE from the local reply port. Native numeric port names and the selector 19 connection producer remain unknown. [Method argument and port evidence](live_lskdd_selector19_binding_report.md) [Mach transport](live_iokit_mach_transport_report.md)

## Evidence and checks

Primary evidence is the installed arm64e slice, UUID `28d510e5-3b91-3916-97ab-b765a3a7ba21`, SHA-256 `a8c3110a3e5f3f4d7d64295218e3a966644c84d2a8c375c7a7b042b6629780c6`. The replay models import results and checks taken indirect transfers against the original chained fixup slots and discriminators. The current IDA database list exposed unrelated binaries, so the findings use byte-backed disassembly and fixups. [Auditor](triage_evidence/audit_live_lskdd_large_frame_transaction.py) [Compressed receipt](triage_evidence/live_lskdd_large_frame_transaction_audit.json.zst)

```sh
python3 triage_evidence/audit_live_lskdd_large_frame_transaction.py "$LSKDD_IMAGE"
```

The auditor uses Unicorn, Capstone, and Apple `dyld_info`. For image bytes N, fixups F, and executed instructions T, setup and replay take O(N + F + T) time. Guest image and stack storage plus the fixup map use O(N + F) space with a fixed stack size. The receipt records selected reads, writes, imported call sites and transfers.

| Assumption and dependent finding | Falsification check |
| --- | --- |
| T1. The preferred addresses and fixups refer to the pinned arm64e image. | Match slice UUID, SHA-256, opcode bytes and chained fixup metadata. |
| T2. Each scenario models a successful lock acquisition and an opaque transaction pointer. The observed create or refresh behavior depends on that state. | Start a fresh guest with counter 0 or seed the prior pointer with counter 1. Compare import arguments, pointer write, counter update and unlock on the same lock. |
| T3. The fixture encodes an initializer state of `0x45b9`. Its continuation and result depend on the full synthetic caller state. | Compare both complete traces. Change the decoded entry word to `0x45a7` with counter 0 and verify the first incompatible fixup. |
| T4. Native selector 19 uses the earlier class binding only if the argument carries that connection. | Correlate the reaching W0 producer, the IOKit object and the ordinary native emission. |

High impact for identifying the previously unnamed transaction helper and its shared state. Medium impact for distinguishing the early frame state from the later selector 19 predecessor contract.

A subsequent caller audit resolves the wrapper that enters the large frame and the recursive block that supplies a child context. [Large-frame caller and recursive context](live_lskdd_large_frame_caller_report.md)
