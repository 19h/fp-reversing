# Installed MIG trace IDs for FairPlayIOKit transport

On macOS build `26C5035r`, the kernel's MIG trace brackets use the dispatch record's **Sandbox filter index** to build their event IDs. The installed Sandbox table assigns IOKit method request `2865` index `117`. After that registration, its dispatch markers are `0xff0001d5` and `0xff0001d6`. The host's trace catalog labels `0xff002cc4` as `MSG_io_connect_method` because that catalog entry encodes the Mach message number. The installed dispatcher uses the index formula below.

## Index provenance

The auditor pins the boot fileset SHA-256 `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`, running kernel UUID `90195379-954d-3ca3-baac-327341f14211` and loaded Sandbox UUID `333049ce-6805-3ffe-9225-302a1ccb80ff`. Addresses are unslid.

| Stage | Installed sites | Data flow |
| --- | --- | --- |
| Initialize kernel MIG buckets | `0xfffffe000c679d94`, `0xfffffe000c679e7c`, `0xfffffe000c679ea4` | Preserve the request ID at record +0 B and initialize the filter index at +4 B to signed −1. The dispatch table uses 24 B records. |
| Register Sandbox indices | Sandbox `_hook_policy_init`, loop `0xfffffe000b7eda00–0xfffffe000b7eda24` | Upon reaching this loop, load the u32 message ID from table `0xfffffe0007d3cee4` at position i and submit `(2, message_id, i)` for i from 0 through 354. The authenticated veneer at `0xfffffe000b82b9b0` uses slot `0xfffffe0008a95b58`. |
| Write the selected bucket | `_proc_set_syscall_filter_index` at `0xfffffe000c31250c`, store at `0xfffffe000c3125a4` | Kind 2 selects the kernel-object MIG table. Match the u32 request ID and require a populated routine pointer. Store the supplied index at record +4 B. |
| Consume the index at dispatch | `0xfffffe000bd3c22c`, `0xfffffe000bd3c68c` | Load the original request ID into W28 from the kernel header at +0x1c B, and the filter index into W23 from the matched routine record. The optional policy callback receives both fields separately. |

The 355 table entries are unique and all match populated records in the reconstructed 358-entry MIG registry. The three populated records outside the Sandbox array have IDs `2408`, `2409` and `2410`. The boot initializer gives them the same initial −1 field. Their later runtime index values are unknown. Public XNU corroborates the role of the index setter and its per-message key. [Kernel MIG registry reconstruction](live_arcade_registration_reply_report.md) [XNU proc filter index API](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_proc.c#L4938-L4951) [XNU message-to-index setter](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/ipc_kobject.c#L343-L362)

## Exact event boundaries

After the relevant policy check, the dispatcher tests bit 0 of `_kdebug_enable` at `0xfffffe000bd3c704`. The enabled branch computes `0xff000001 | (u32(index) << 2)` and calls `_kernel_debug` at `0xfffffe000bd3c8b0`. The branch then rejoins the routine call path, which invokes the selected MIG stub at `0xfffffe000bd3c724`. On a normal return the dispatcher checks the enable bit again at `0xfffffe000bd3c730`. Its enabled arm computes `0xff000002 | (u32(index) << 2)` and calls the logger at `0xfffffe000bd3c8d4`. Both shifts truncate to 32 bits. If the initial index −1 reaches this computation, the proposed arguments are `0xfffffffd` and `0xfffffffe`. Event recording depends on the tracing state and logger.

Both sites clear X1 through X4. The logger reads the current thread ID from thread +0x510 B into X5 before its common continuation. The original `thread_tid` accessor reads the same field. The markers can bound a stub invocation on a correlated trace thread. They carry no selector, task-local Mach name, user-client address, returned status, or reply identifier. The post-stub marker occurs before the common reply disposition check, queue submission and user receive. The separate request-ID lookup, transport and reply analysis supplies those stages. [XNU kernel debug emitter](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kdebug.c#L831-L838) [IOKit transport and reply stages](live_iokit_mach_transport_report.md)

| Kernel MIG request | Mach request ID | Index from Sandbox | Dispatch start | Dispatch end |
| --- | ---: | ---: | --- | --- |
| Get IOKit main port | 205 | 5 | `0xff000015` | `0xff000016` |
| Iterator next | 2802 | 55 | `0xff0000dd` | `0xff0000de` |
| Service close | 2816 | 69 | `0xff000115` | `0xff000116` |
| Service open extended | 2862 | 114 | `0xff0001c9` | `0xff0001ca` |
| Connect method | 2865 | 117 | `0xff0001d5` | `0xff0001d6` |
| Class match | 2881 | 133 | `0xff000215` | `0xff000216` |
| Task info | 3405 | 195 | `0xff00030d` | `0xff00030e` |
| Arcade registration | 51471 | 347 | `0xff00056d` | `0xff00056e` |

## Diagnostic reach

The installed Mach trap entry and exit records can add task-local request header names and transport status when correlated on the same thread. [Installed Mach trap trace](live_mach_trap_trace_report.md)

The host's `ktrace decode` accepted all 18 checked IDs, including both phases for the eight selected requests and the initial-index pair. It labels `0xff000115` as `MSG_mach_notify_port_destroyed`, even though the installed producer can emit that value for service close after Sandbox registration. It leaves the index-117 method markers unnamed. The read-only `ktrace info` query returned exit status 1 with an `EREMOTE` diagnostic. Session state and actual emitted records are unknown. The report retains a reproducible code map and no native trace capture.

A correlated method marker establishes arrival at a generic IOKit MIG stub on the selected thread. Attributing that arrival to FairPlay selector 26 requires the corresponding connection object or namespace identity and the selector. A matched reply is needed to establish delivery and operation status. The earlier RAX capture contains a failed open and zero printed method requests. The prior daemon registry observations supply creator and attachment IDs for a different observation. [Archived open and Mach request counts](archived_iokit_open_retirement_report.md) [Native client creator attribution](live_iokit_open_owner_report.md)

## Assumption register

| Assumption | Dependent result | Falsification check |
| --- | --- | --- |
| A1. The measured kernel and Sandbox images correspond to the running installation. | All sites, table bytes and import bindings. | Re-read build, fileset hash and loaded UUIDs, then compare original instruction words and the chained veneer pointer. |
| A2. Startup reaches the Sandbox registration loop and the selected routine retains the assigned index. | Exact codes in the event table when the dispatcher emits them. | Reconstruct the table and populated MIG ID set, verify the initial and registration stores, and compare a transaction-linked native trace to the computed values. |
| A3. The request passes the relevant policy path and returns normally from the selected stub. | The two trace call sites bracket that dispatch. | Verify the entry and exit enable checks, policy rejection branch, calls and continuation branches. Tracing filters and loss may further affect retention. |
| A4. The local catalog is the one consulted by the decoder. | Observed labeling collision. | Compare the installed catalog digest and numeric lookup with the live `ktrace decode` output. The label provides no independent producer attribution. |

**High impact.** A search keyed to the catalog name for `2865` would miss its expected installed MIG markers after Sandbox registration. **Medium impact.** One catalog label also collides with the code derived for service close. Numeric IDs and the build-specific index table support correct attribution.

Run `python3 -B triage_evidence/audit_live_iokit_mig_trace.py "$BOOT_FILESET"` with the repository Python dependencies. For B fileset bytes and R examined routine records, the collector retains O(B + R) data and performs O(B + R) input work, excluding operating-system tools and the bounded hash collision reconstruction reused here. [Auditor](triage_evidence/audit_live_iokit_mig_trace.py) [Compressed receipt](triage_evidence/live_iokit_mig_trace_audit.json.zst)
