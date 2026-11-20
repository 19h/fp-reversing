# Installed Mach trap trace for IOKit connection and reply names

The installed ARM64 Mach trap dispatcher can record the two task-local names from a `mach_msg2_trap` send. For an ordinary IOKit method call, these are the destination connection and the header's reply name. A separate trap exit reports the Mach transport result. The same-thread MIG markers for request 2865 identify the generic IOKit method dispatch within that trap interval when all four records are retained. The selector, connection-to-client binding and IOKit result still require transaction evidence. [Installed MIG trace IDs](live_iokit_mig_trace_report.md) [Installed IOKit request packing](live_iokit_mach_transport_report.md)

## Emission sites and record layout

These are unslid addresses on build `26C5035r`, kernel UUID `90195379-954d-3ca3-baac-327341f14211`. The installed trap table identifies row 47 as `mach_msg2_trap`, with eight LP64 arguments and an authenticated binding to `0xfffffe000bd25630`. The syscall dispatcher at `0xfffffe000bebfb50` negates the saved trap number, indexes 24 B rows and copies 64 B from the saved LP64 argument registers. The entry trace runs before the Mach trap policy check and handler call. [Pinned ARM64 trace source](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/arm64/bsd_arm64.c#L163-L243)

| Record | Trace ID for trap -47 | Installed logger call | Contents |
| --- | --- | --- | --- |
| Trap entry | `0x010c00bd` | `0xfffffe000bebfd28` | Read four 64-bit arguments from the saved frame before policy evaluation. |
| Trap exit, dispatcher return | `0x010c00be` | `0xfffffe000bebfd78` | Put the sign-extended 32-bit trap result in arg1 and zeros in arg2 through arg4. A policy rejection can also reach this exit. |
| Trap exit, Mach receive continuation | `0x010c00be` | `0xfffffe000bec9a84` | Put the 32-bit receive result in arg1, zero-extended by a W-register write. Clear arg2 through arg4. The continuation passes the result at `0xfffffe000bd25038`. |

The dispatcher inserts the negated trap number at bit 2 of `0x010c0000` and adds phase 1 or 2. The continuation derives the same exit code from the saved trap number. Compare status as u32 because sign extension differs between the two exits. Each path tests bit 0 of `_kdebug_enable`. The shared `_kernel_debug` entry gets the current thread ID from thread +0x510 B and supplies it as arg5. The host decoder labels both codes `MSC_mach_msg2_trap`. [Pinned ARM64 return source](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/arm64/bsd_arm64.c#L261-L274) [Pinned Mach receive continuation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/mach_msg.c#L364-L373) [Pinned logger and filters](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kdebug.c#L769-L838)

| Entry field | Saved register | Interpretation on the ordinary send/receive path |
| --- | --- | --- |
| arg1 | X0 | Caller buffer address. A vector call uses the data argument for its vector array. |
| arg2 | X1 | Mach call options. Bits 0 and 1 request send and receive respectively. |
| arg3 | X2 | High u32 is send extent in bytes on the nonvector path. Low u32 is the header bits word. |
| arg4 | X3 | High u32 is the request's local reply name. Low u32 is its remote destination name. |
| arg5 | Logger | Thread ID. The logger does not copy user X4. |

The kernel trap unpacks X3 and X4 into adjacent u32 header fields at `0xfffffe000bd2587c` through `0xfffffe000bd25888`. The X4 halves are the voucher name and message ID. The receive path consumes X5.high as its receive name at `0xfffffe000bd2596c`. X4 and X5 are outside the trap entry record. An ordinary installed IOKit request supplies the same cached reply name in X3.high and X5.high, making the recorded header name a candidate receive name for that wrapper. The actual receive selector still requires wrapper or transaction attribution. [Pinned Mach message trap ABI](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/mach_msg.c#L870-L951) [IOKit reply-name cache](live_iokit_mig_reply_port_report.md)

## Control and native correlation

The installed Mach port description query supplies a registry entry ID for an IOKit connection name when the task namespace is available. Two simultaneous local controls joined distinct connection names to distinct child entries. [IOKit port descriptions](live_iokit_port_description_report.md)

The auditor reinterprets two adjacent pairs of 32-bit words from each of the five retained native verifier request headers as the would-be arg3 and arg4 values. All five reproduce the recorded header bits, send extent and namespace names. For the verifier's open, arg3 would be `0x5080001513` and arg4 `0x70700001a03`. The prior capture observed transport result zero, reply 2962, a null connection and IOKit status `0xe00002c2`. This demonstrates that a successful Mach transport result alone leaves the IOKit outcome open. The verifier's headers came from an earlier capture of its own process. The reconstructed values are derived event arguments. [Native verifier capture](live_iokit_mach_headers_report.md)

An existing authorized trace with complete per-thread records can support the following correlation. Pair entry and exit by thread ID and timestamp, reject intervals with loss or ambiguous pairing, and require the method MIG start and end inside the same trap interval. On the installed Sandbox assignment that pair is `0xff0001d5` and `0xff0001d6`. Arg4 of the enclosing trap entry identifies the numeric names in the traced task. Confirm the thread's process generation before reusing those names and establish the destination right's binding to the FairPlayIOKit client independently. A successful open reply or equivalent per-task object attribution can support that binding while the right remains live. The selector, received reply ID and method result require additional observation. Port names can be reused after right retirement. For N ordered records and T active threads, the per-thread interval check takes O(N) time and O(T) pending storage for single-depth intervals. [Client creator and ownership](live_iokit_open_owner_report.md) [Installed MIG trace IDs](live_iokit_mig_trace_report.md)

The read-only `ktrace info` query on this host again returned exit status 1 and an `EREMOTE` diagnostic. Session state and eligible records remain unknown. Source documents build-specific instrumentation and process filtering. Neither the installed emitter nor the catalog proves that this host can retain all four events for the daemon. [Pinned instrumentation levels](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/kdebug_kernel.h#L233-L255) [Pinned trace record conditions](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kdebug.c#L769-L816)

## Assumption register and verification

| Assumption | Dependent result | Falsification check |
| --- | --- | --- |
| The measured fileset corresponds to the installed kernel. | Selected locations, table row and argument loads. | Compare build, runtime UUID, fileset digest, authenticated table binding and original instruction words. |
| The method uses the ordinary LP64 synchronous IOKit stub and the selected trace is complete. | X3 names have the expected header roles and bracketed events can be joined. | Check the wrapper image and event options, process generation, thread and timestamps. Reject ambiguous or incomplete intervals. |
| A destination name still denotes the connection that a separate observation attributed to FairPlayIOKit. | Registry-client attribution. | Require matching namespace and right lifetime through the call. A matching registry creator PID alone is insufficient. |
| The receipt describes the earlier native verifier's original headers and transport results. | Derived arg3 and arg4 examples. | Compare every packed word against the header decode and independently inspect both status channels in the last exchange. |

High impact for recovering task-local connection and reply names from a retained trap record. Medium impact for recognizing the same exit code after a receive continuation and distinguishing its status from the IOKit result. The read-only auditor checks the original fileset, trap table, instruction words, two decoder labels and five prior native exchanges. Run `python3 -B triage_evidence/audit_live_mach_trap_trace.py "$BOOT_FILESET"` on the pinned build with Capstone and zstd available. [Auditor](triage_evidence/audit_live_mach_trap_trace.py) [Compressed receipt](triage_evidence/live_mach_trap_trace_audit.json.zst)
