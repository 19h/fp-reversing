# fairplaydeviceidentityd DeviceIdentity completion and outputs

The installed arm64e daemon adapts the asynchronous DeviceIdentity certificate API to a synchronous local call at `0x100001130`. The completion receives a `SecKeyRef`, an `NSArray`, and an `NSError`. It publishes the key and a certificate array when the array count is exactly two. The direct scheduled caller passes five null output pointers and consumes the returned status. Two protected call sites can reach the same wrapper through an authenticated dispatch-table entry and supply all five output addresses. Their native reachability and the provider's transport are unknown. [Startup and activity entry](live_fpdi_startup_report.md)

## Issue, wait and publish

| Site | Operation | Evidence |
| --- | --- | --- |
| `0x10000117c`, `0x1000011a4` | Check `DeviceIdentityIsSupported`, then create a dispatch queue. | False returns status 4. A null queue returns status 3. Both exits precede the certificate call. |
| `0x100001244` | Convert the incoming mode to `NSNumber` with `numberWithUnsignedChar:`. | The object is stored among the dictionary values paired with the imported `kMAOptionsBAASkipNetworkRequest` key. The symbol identifies the option. The provider's behavior under either value is unobserved. |
| `0x10000130c` | Create a zero-count semaphore. | X0 is zero at the call. The retained semaphore is captured at block offset `+0x20`. |
| `0x1000013dc` | Call `DeviceIdentityIssueClientCertificateWithCompletion`. | X0 is the queue, X1 the options dictionary, and X2 the stack block. The original authenticated stub resolves through slot `0x1005e9d00`. |
| `0x1000013e8` | Call `dispatch_semaphore_wait`. | X0 carries the same semaphore. X1 is all ones, the dispatch forever value. |
| `0x1000017ec` | Call `dispatch_semaphore_signal` from the callback. | X0 comes from capture `+0x20`. The status and result stores occur before the signal on ordinary completion paths. |
| `0x1000015e0` | Return the status to the caller. | The normal post-wait path loads the 4 B status at `0x100001578` and returns its zero-extended value. |

The stack block's signed invoke points to `0x100001658`. Its descriptor at `0x1005c0040` declares a 64 B block. The signature pointer at `0x1005c0060` rebases to `0x1005be9ce`, which contains `v32@?0^{__SecKey=}8@"NSArray"16@"NSError"24`. The callback's X0 is the block, X1 the key, X2 the array, and X3 the error. The wrapper and callback access the captures through the Blocks byref forwarding pointers at record offset `+8`.

| Block offset | Capture | Initial payload | Forwarded payload |
| --- | --- | --- | --- |
| `+0x20` | Retained dispatch semaphore | Zero-count semaphore | Direct capture |
| `+0x28` | Status byref | 2 | 4 B at `+0x18` |
| `+0x30` | Certificate array byref | Null | 8 B at `+0x28` |
| `+0x38` | Key byref | Null | 8 B at `+0x18` |

The block descriptor references copy and dispose helpers at `0x100001818` and `0x100001880`. The copy helper retains the captured semaphore and assigns all three byrefs with flag 8. The dispose helper disposes the three byrefs and releases the semaphore. The array byref also has move and destroy helpers at `0x100001640` and `0x100001650`.

## Completion decisions and ownership

| Array count at `0x10000169c` | Error | Status store | Output publication |
| --- | --- | --- | --- |
| 2 | Null | 0 at `0x10000179c` | Copy the array and save the key. |
| 2 | Nonnull | 1 at `0x1000016b8` | Copy the array and save the key. The optional log at `0x100001714` describes expired BAA certificates. |
| Any other count | Either | 2 at `0x100001730` | Skip the result stores. The optional log at `0x10000178c` records failure to obtain BAA certificates. |

The callback retains the array and error arguments and releases those references after signaling. On the two-element path it sends `copy` at `0x1000017a4`, stores the resulting reference at `0x1000017b4`, and releases the previous value in the byref. It writes the incoming key pointer at `0x1000017c8`. The callback releases a nonnull key at `0x1000017e4` when the forwarded key cell is still null. After wakeup, a populated array cell gates the caller output path. The wrapper transfers the saved key to a supplied out pointer or releases it at `0x100001420`. On a null array cell the wrapper returns through the status and cleanup path without writing to any optional output.

## Synchronous wrapper outputs

| Entry register | Optional result | Write site |
| --- | --- | --- |
| X1 | `SecKeyRef` transferred to caller | `0x100001404` |
| X2 | Allocated certificate byte buffer from array index 0 | `0x1000014b4` |
| X3 | 4 B certificate length for index 0 | `0x1000014bc` |
| X4 | Allocated certificate byte buffer from array index 1 | `0x100001550` |
| X5 | 4 B certificate length for index 1 | `0x100001558` |

Both byte-buffer routes call `objectAtIndexedSubscript:`, `SecCertificateCopyData`, and `CFDataGetLength` in that order. If the returned length is L, the allocation and `CFDataGetBytes` range use L modulo 2^32 B. The copy range starts at byte 0. Each temporary `CFData` is released locally. The paired length receives the same low 32 bits of L when supplied. If the buffer output pointer itself is absent, the wrapper skips conversion for that index and writes zero to the supplied length pointer. If allocation returns null, the wrapper sets status 3 and stores a null buffer while preserving the computed length in its paired output. The two indices are processed independently, so status 3 can accompany a transferred key or a successfully copied certificate from the other index.

## Scheduled caller and cross-layer boundary

A scan of immediate `B` and `BL` targets in `__TEXT,__text` found exactly two branches to the wrapper, both in the scheduled prefetch routine. The call at `0x100000e74` passes mode 1. Status 0 goes directly to the common analytics and return path. Status 1 can also reach that path after the threshold test at `0x100000e90`. The other outcomes reach the mode 0 call at `0x100000ec8`. Both calls pass X1 through X5 as zero. In this caller, a saved key is released locally and neither certificate is copied into a caller buffer.

Dyld records an authenticated rebase at `0x1005e7aa0`, slot `0x4e04` relative to the recovered dispatch-table base `0x1005c0a80`. It resolves to the wrapper with IA diversity `0xf447` and address diversity disabled. This identifies one destination in the protected table. Two protected call sites conditionally select that entry and pass addresses for all five output values. The reaching table pointers, incoming request, and any link to an XPC reply or the FairPlayIOKit connection remain unknown. [Protected caller evidence](live_fpdi_deviceidentity_callers_report.md) The certificate request and completion carry a local block and a dispatch semaphore. The evidence establishes no provider-side Mach message ID, port right, or IOKit selector. [Daemon XPC peer worker](live_fpdi_xpc_report.md) [Candidate FairPlayIOKit call](live_fpdi_selector26_caller_report.md)

## Assumption register

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| D1 | The installed slice matches the build under investigation. Every address and fixup in this report depends on its UUID and SHA-256. | Hash the target slice and compare `LC_UUID` before applying the mappings. |
| D2 | The provider calls the block with the argument types in its descriptor and the Objective-C values exhibit their normal selector semantics. The result classes and predicate interpretation depend on this contract. | Compare the provider's invoke site or an ordinary completion record against the signature and observed array count. |
| D3 | The provider performs one ordinary completion and its key reference remains valid through the signal. The ownership trace describes one invocation through the shown code. | Trace one native request with callback invocation count, block copy and disposal, and key release or transfer. |
| D4 | Optional output pointers supplied by an indirect caller refer to writable, live storage. The table above identifies where stores would occur when such arguments are present. | Resolve an incoming protected call to table index `0x4e04` and follow X1 through X5 to their producers and post-call consumers. |

High impact for distinguishing the scheduled certificate warm-up from a result-bearing use of the wrapper. The authenticated table entry gives a concrete target for finding that use. Medium impact for interpreting status 3 alongside partially populated outputs.

## Reproduction

Primary evidence is the installed arm64e slice from macOS build `26C5035r`, UUID `0a404c50-4901-312f-9e36-04565d30f305`, SHA-256 `f73ababfd9265e1bdacde11467d5a3701cec634c49ce3a65f5769cf5ccd843f0`. Instruction addresses are preferred virtual addresses. The audit checks 84 instruction anchors, 35 imported call sites, five Objective-C selectors, six additional fixups, the block descriptor and the immediate branch census. The compressed receipt preserves 556 decoded instructions. With B input bytes, F decoded fixups and I retained instructions, the audit takes O(B + F + I) time and space. It verifies static evidence. Native completion count, provider-side I/O, and the protected call into the wrapper are unobserved. [Auditor](triage_evidence/audit_live_fpdi_deviceidentity_completion.py) [Compressed receipt](triage_evidence/live_fpdi_deviceidentity_completion_audit.json.zst)

    python3 -B triage_evidence/audit_live_fpdi_deviceidentity_completion.py DAEMON
