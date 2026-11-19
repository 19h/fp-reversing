# IOService termination and FairPlay provider stop on macOS 26C5035r

FairPlay `clientClose` passes options zero to inherited `IOService::terminate` and returns zero after the call. When phase one admits phase-two scheduling, the request goes through the asynchronous queue. The termination worker can then dispatch FairPlay `stop` with the client and its provider. The stop override gives the obfuscated cleanup routine the address of the same context cell used by the startup adapter. A native transaction reaching this sequence remains unverified. [Connection retirement](live_fairplay_connection_retirement_report.md)

```text
clientClose -> terminate(0) -> phase one
                                 |
                     eligible phase-two queue
                                 |
                     termination worker, eligible stop pair
                       |                         |
                 work-loop gate             direct call
                       |                         |
                       +---- actionStop ---------+
                                  |
                         FairPlay stop(client, provider)
                                  |
                     saved provider + &client.context
                                  |
                          _kratpzs81h(cell)
                                  |
                      inherited stop -> clear provider/task
```

## Termination and stop dispatch

The auditor checks the original installed collection, kernel and FairPlayIOKit UUIDs and running kernel UUID. Addresses below are preferred and unslid. The Apple source tag `xnu-12377.121.6` corroborates the names and semantics of the selected IOService scheduling and dispatch edges. [XNU termination options](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/iokit/IOKit/IOService.h#L96-L104) [XNU phase-one scheduling](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/iokit/Kernel/IOService.cpp#L2743-L2755)

| Transition | Unslid sites | Recovered contract |
| --- | --- | --- |
| Close to phase one | `0xfffffe000a545618`–`0xfffffe000a545624`, `0xfffffe000c52629c` | The FairPlay vtable at +0x630 selects inherited `terminate`. It adds option `0x04` and enters `terminatePhase1`. FairPlay sets its own return to zero after the call. |
| Schedule phase two | `0xfffffe000c5272c8`–`0xfffffe000c5272d8`, `0xfffffe000c51f044`, `0xfffffe000c51f078`, `0xfffffe000c51f0fc` | The selected phase-one edge sets the phase-two-ready bit and passes the options through. The scheduler checks inactive and phase-two-ready state. With synchronous bit `0x02` clear, it takes the asynchronous branch. |
| Publish and consume pending work | `0xfffffe000c51f508`, `0xfffffe000c51f518`, `0xfffffe000c51f5a0`, `0xfffffe000c51fa44` | The scheduler publishes the service through the termination-array slot and increments the work counter, with wakeup on its zero-to-one transition. The worker reads the same array's index-zero entry. Worker readiness and the later stop pair have their own conditions. |
| Dispatch the selected stop pair | `0xfffffe000c520654`, `0xfffffe000c52069c`–`0xfffffe000c520700` | The worker calls virtual `provider->getWorkLoop()`. On a nonnull result it passes a signed pointer to the stop action at `0xfffffe000c521ea4`, followed by provider and client, into vtable +0x1c0. On null it calls the same action directly with provider in X0 and client in X1. |
| Work-loop gate | `0xfffffe000c569030`, `0xfffffe000c56904c`, `0xfffffe000c569078` | The recovered `IOWorkLoop::runAction` binding closes the gate, authenticates and calls the action with the same arguments, then opens the gate. This route uses the work-loop gate in the calling context. |
| Action to FairPlay stop | `0xfffffe000c521fac`–`0xfffffe000c521fc4` | Reorders the two action arguments so that X0 is the client and X1 is the provider. The +0x5f8 client vtable slot selects FairPlay `stop` at `0xfffffe000a545570`. After return, the action conditionally closes the provider's open relationship and then calls the client's detach method. |

The asynchronous queue is the phase-two scheduling boundary. Once the worker reaches the stop action, a work-loop binding adds serialized execution through its gate. Timing of the framework close reply, wrapper name deallocation, phase-two work and final object deallocation is unknown for a live FairPlay connection. [XNU asynchronous scheduling](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/iokit/Kernel/IOService.cpp#L2803-L2877) [XNU stop action and worker](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/iokit/Kernel/IOService.cpp#L3142-L3205) [XNU worker stop selection](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/iokit/Kernel/IOService.cpp#L3355-L3385) [XNU work-loop action](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/iokit/Kernel/IOWorkLoop.cpp#L564-L576)

## Provider context ABI and death byte

| Interface | Unslid sites | Argument and state transfer |
| --- | --- | --- |
| Startup | `0xfffffe000a5454d4`, `0xfffffe000a545524`, `0xfffffe000a545558` | Clears the u64 cell at client +232 B and stores the cast provider at +216 B. For the nonnull provider branch, X0 is provider, X1 is `&client[+232 B]`, W2 is mode from +240 B and X3 is task from +224 B. |
| Startup adapter | `0xfffffe000a546314`–`0xfffffe000a546324` | Provider vtable +0xa10 resolves to `Trped0719ab`. It drops the provider and tail-calls `_lapsl183ah` with cell, mode and task. After a normal return, the enclosing startup sets W0 to 1. |
| Stop | `0xfffffe000a54558c`, `0xfffffe000a5455ac`–`0xfffffe000a5455b4` | X0 is loaded from the saved provider at +216 B. X1 is `&client[+232 B]`. The separately received provider argument is preserved for the base stop call. |
| Stop adapter | `0xfffffe000a546308`–`0xfffffe000a546310` | Provider vtable +0xa18 resolves to `LasdMdn12cas`. It drops the provider and tail-calls `_kratpzs81h` at `0xfffffe000a6677d8` with the cell address in X0. |
| Stop completion | `0xfffffe000a5455c4`–`0xfffffe000a5455dc` | On an ordinary return, invokes the inherited `IOService::stop` with the original client and provider argument, then clears the saved provider/task pair. The wrapper supplies no explicit store to the context cell after the adapter returns. |
| Death byte | `0xfffffe000a545478`, `0xfffffe000a545638` | Successful initialization stores zero at client +244 B. `clientDied` stores one before base dispatch. The supplied earlier decompilation agrees with the placement of the death store. |

The 248 B class size includes the +244 B byte. A linear decode over the kext's 1,687,188 B executable text section examined 421,797 four-byte words. Capstone left 51 words undecoded. It found 44 literal `[base, #0xf4]` matches including stack references and larger-width operations. The two byte stores in the table were the only byte-width accesses found by this operand filter. The scan leaves the byte's downstream role unknown because wider, rebased and register-indexed accesses require object provenance. The two provider adapters have an internal C++ call ABI. Existing source analysis of the earlier build identifies a typed context constructor and a selected typed-free path inside the corresponding callees. The current report pins the software handoff up to those callee entries. [Historical context lifecycle](userclient_context_lifecycle_report.md)

## Assumption register

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| S1 | The audited collection corresponds to the reported build. All addresses and chained bindings are build-specific. | Rehash the fileset and match the kernel and kext UUIDs independently. |
| S2 | Phase one reaches the scheduling branch and the scheduler admits the service. The asynchronous queue result depends on those conditions. | Check the readiness, inactive and synchronous-bit branches independently against the original words. |
| S3 | The selected worker pair contains the FairPlay class and provider. The recovered vtable bindings describe that dispatch. | Match both runtime object classes and arguments on the same transaction. Compare the direct action and work-loop-gated alternatives. |
| S4 | The provider adapter returns normally. The inherited stop and pair clear depend on that return. | Verify the instruction order, preserving the saved provider and the separate incoming provider argument. Recover the callee's return and cell-store paths for the same build to establish full completion. |
| S5 | The field census covers its declared literal addressing form. Wider or aliased readers are unknown. | Check the two store words directly, rescan the complete text section and enumerate the undecoded slots. A wider load through a proven client alias would extend the result. |

High impact for separating daemon-visible close from deferred kext cleanup and for identifying the provider/context ABI. Medium impact for work-loop gate attribution and tracing the subsequent close and detach. Low impact for the direct death-byte census until object-specific consumers are recovered.

QG1 covers factual scope. QG2 gives the premises and probes. QG3 covers the queue, callback, argument registers and context boundary. QG4 checks 4 B instruction geometry, the 248 B class size and exact field offsets. QG5 records the conditional worker dispatch and unverified native order. QG6 checks original instructions, chained bindings and released Apple source. QG7 bounds the effect of each finding. Collection parsing uses O(B + F) time and space for B input bytes and F fixups. The displacement scan uses O(T) time for T executable bytes, one 64 KiB decode chunk and storage proportional to the matched and undecoded words, plus the T-byte section slice. [Audit script](triage_evidence/audit_live_fairplay_provider_stop.py) [Compressed receipt](triage_evidence/live_fairplay_provider_stop_audit.json.zst)

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_provider_stop.py "$CURRENT_COLLECTION"
```
