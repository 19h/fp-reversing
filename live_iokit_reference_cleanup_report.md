# FairPlayIOKit connection-reference cleanup during termination

In the installed kernel for macOS `26C5035r`, the selected phase-one termination path marks the user client inactive, calls termination notifiers and invokes `IOUserClient::destroyUserReferences`. This occurs on the phase-one call stack, before the selected phase-two scheduling edge. Deferred finalization has its own queue and active-IPC check. The reference-cleanup path can remove the association between the original Mach connection port and the FairPlay user client before that queue runs. [Pinned XNU phase one](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOService.cpp#L2636-L2697) [Provider termination and scheduling](live_fairplay_provider_stop_report.md) [Deferred finalization](live_iokit_method_locking_report.md)

```text
FairPlay clientClose -> IOService::terminate(0) -> phase one
    -> inactive state -> termination notifiers -> destroyUserReferences
        -> connection unlink on lookup hit -> owner-record cleanup
    -> eligible phase-two scheduling -> later finalize eligibility check

Mach no-more-senders callback -> eligible connection unlink
    -> same owner-record cleanup -> selected clientDied
```

## Connection-reference cleanup

Addresses are preferred and unslid. The auditor matched the boot fileset digest and both embedded UUIDs to the host build, running kernel UUID and loaded FairPlayIOKit UUID. The installed words and chained pointer records give the following bindings. [Pinned XNU reference cleanup](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L321-L394)

| Transition | Installed site | Effect |
| --- | --- | --- |
| Publish inactive state | `0xfffffe000c5264d8` through `0xfffffe000c5264f0` | Tests state word 0 bit 0. On the selected transition, writes both state words at service +72 B. The loaded OR mask sets word 0 bit 0. |
| Invoke user-reference cleanup | `0xfffffe000c526af8`–`0xfffffe000c526bb4` | The did-inactivate branch obtains termination notifiers and invokes any found before passing the same victim in X0 to `destroyUserReferences` at `0xfffffe000c5b60dc`. |
| Ordinary object reference | `0xfffffe000c5b6100` | Calls the object-reference helper with type `0x28`. The installed helper preserves the IOService association when its hold-destroy bit is set. |
| Find and detach connection association | `0xfffffe000c5b6170`–`0xfffffe000c5b6254` | Under the global port-object lock, searches the bucket for the same object and type `0x27`. On a hit it clears the hashed flag, unlinks the wrapper and disables its connection association. The disable helper writes an authenticated null at port +80 B. A miss exits after unlocking. |
| Transfer mappings state | `0xfffffe000c5b625c`–`0xfffffe000c5b626c` | For an IOUserClient hit, loads the mappings object from client +144 B, clears the field, and calls the owner-record cleanup. The null-mappings branch skips adoption. |
| Adopt an existing port | `0xfffffe000c5b6274`–`0xfffffe000c5b628c` | With mappings present, creates an IOMachPort wrapper for the mappings object, copies the old wrapper's port to it, re-enables that same type-`0x27` port with the new association, and clears the old wrapper's port pointer. |
| Release retained objects | `0xfffffe000c5b62d0`, `0xfffffe000c5b633c` | Releases the prior mappings reference on the nonnull path and releases the old wrapper after the global lock is dropped. |

The adoption branch changes the kernel object's association on the existing port. It allocates a wrapper, reuses the port and emits no port descriptor at this transition. The type-`0x27` close implementation separately recognizes an imported `OSSet` at `0xfffffe000c5be7e0`–`0xfffffe000c5be7e4` and returns success without dispatching `clientClose` on it. Apple's published source identifies that arm as the mappings case. The installed bytes establish the conditional behavior. A native FairPlay client with a populated mappings field remains unverified. [Pinned XNU IOMachPort adoption](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L172-L191) [Pinned XNU close](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L4611-L4635) [Connection messages and right publication](live_fairplay_connection_report.md)

## Owner records

Phase one calls the owner cleanup at `0xfffffe000c5b6268`. The eligible Mach no-more-senders path reaches the same helper at `0xfffffe000c5b5be8` after it has disabled the association and identified an IOUserClient. This internal helper corresponds to `IOUserClient::noMoreSenders`. It removes task ownership records. The separate `clientDied` call belongs to the eligible Mach no-more-senders callback after association removal. [Pinned XNU no-more-senders cleanup](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L273-L305) [Connection retirement and message 70](live_fairplay_connection_retirement_report.md)

| Field or operation | Installed sites | Effect |
| --- | --- | --- |
| Acquire owners lock | `0xfffffe000c5b5ca4`, `0xfffffe000c5b5cbc` | Uses the same owners lock as registration. The lock pointer slot is `0xfffffe000cbd7898`. |
| Select first owner | `0xfffffe000c5b5ccc` | Reads the client-side queue head at client +160 B. |
| Unlink from task | `0xfffffe000c5b5d10`, `0xfffffe000c5b5d50`–`0xfffffe000c5b5d74` | Removes the task-side links at record +8 B and +16 B from the queue at task +1616 B. |
| Recompute suspension interest | `0xfffffe000c5b5d78`–`0xfffffe000c5b5dc0` | Scans the remaining task owners for message-app-suspended interest at bit 0 of each client's +155 B byte, then updates task state. |
| Unlink from client and free | `0xfffffe000c5b5dc4`–`0xfffffe000c5b5e20`, `0xfffffe000c5b5cfc` | Removes record +32 B and +40 B from the client queue, frees the typed record, and clears the client owner head and tail when drained. |

These fields match the 48 B records linked by open. For a client with N owners, the owner drain uses O(N + sum of inspected task-queue lengths) work and O(1) auxiliary space, excluding lock wait and deallocation internals. The association search is linear in the selected bucket length. [Pinned XNU owner drain](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L1740-L1769) [Open owner registration](live_iokit_open_owner_report.md)

## Assumption register and verification

| Premise | Dependent result | Falsification probe |
| --- | --- | --- |
| The pinned fileset matches the running kernel and FairPlayIOKit. | Installed instructions, symbols and vtable bindings. | Compare the digest and fileset UUIDs, then query the running kernel and loaded driver UUIDs. |
| The selected victim makes the phase-one inactive transition. | The path reaches termination notification and reference cleanup before the selected schedule call. | Decode both control-flow paths and check the inactive-state write and cleanup operand. |
| The same client still has a registered connection wrapper. | Phase one disables that binding and invokes owner cleanup. | Pair the object/type lookup with a native association record for the same client. A bucket miss selects the installed early return. |
| The client holds a mappings object at cleanup time. | The original port is adopted by the new mappings wrapper. | Confirm the +144 B field and the pre- and post-cleanup association on the same ordinary connection. |

High impact for distinguishing connection-association removal from deferred finalization and daemon-side name release. Medium impact for identifying the teardown of both owner queues and the conditional mappings handoff. The original kernel image proves the selected static interfaces. Native association, owner removal, mappings adoption and final send-right retirement on a matched FairPlay exchange remain unknown.

The audit verifies 97 original AArch64 instructions, seven symbols, two chained vtable bindings and both pairs of 32-bit state masks. It checks the current build and kernel and kext UUIDs with `--observe`. The run only reads the collection and host identity data. For B collection bytes, F fixups and I instruction sites, the audit uses O(B + F + I) time and space, excluding host identity queries. [Audit script](triage_evidence/audit_live_iokit_reference_cleanup.py) [Compressed receipt](triage_evidence/live_iokit_reference_cleanup_audit.json.zst)

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_iokit_reference_cleanup.py "${CURRENT_COLLECTION}" --observe
```
