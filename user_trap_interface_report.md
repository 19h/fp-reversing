# User-library trap interfaces: Mach messages, BSD file/VM calls and RAX resumption

The available libsystem_kernel image connects the recovered daemon call sites to concrete ARM64 trap interfaces. Its ordinary mach_msg API packs a Mach2 register packet and reaches SVC at `0x180547c1c` with X16=-47. Its file/VM APIs use separate positive BSD selectors. The mmap wrapper adds validation and flags below the daemon: size zero is rejected before a trap, while accepted calls add MAP_UNIX03.

The supplied trace also has a newly reconciled control-flow detail: 27 printed Mach2 trap observations correspond to 22 printed send headers plus five identical-packet resumptions. Each extra observation follows return 0x80000001 and an intervening host reply, without another bridge-send log. The inspected RAX source defines that value as its internal RESTART marker and preserves receive-stage progress. Historical producer identity remains unknown; this is not evidence of five duplicate sends.

## Provenance and assumption register

The original installed cache UUID remains `2bd06591-e751-3e84-963f-b08dab6af23a`. The inspected `/usr/lib/system/libsystem_kernel.dylib` UUID is `f2bceb9a-0fec-3c92-b6ea-8e37157050a8`; libSystem.B UUID is `deaf2098-8edd-3e5d-a821-f63a14d6c055`. LibSystem.B contains an LC_REEXPORT_DYLIB path to libsystem_kernel, whose original export trie supplies the API identities below. This is an available static linkage path; actual dyld resolution, interposition and runtime module identity are unverified.

[Contracts](triage_evidence/user_trap_contracts.json) retain 24 original LC_FUNCTION_STARTS-bounded cache ranges, original nlist/export names, 12 raw trap veneers, data-cell provenance, five full-domain arithmetic/predicate proofs, 32 private wrapper fixtures, nine packet checks and four hashed cache source files. Addresses are unslid source coordinates. Original daemon bindings are separately decoded from the arm64e slice SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.

The supplied collection remains SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, kernel UUID `9b65bd6e-027b-34d1-a22b-ac03dccffc84`. Its exact `_version` symbol at `0xfffffe0007045493` contains `Darwin Kernel Version 27.2.0`, build `xnu-13432.41.4~3/RELEASE_ARM64_T6041`. This is static collection identity, not the historical trace host's identity. Selected dispatch/table names were not found among its 6951 kernel nlist entries. The follow-up [kernel dispatch report](kernel_dispatch_report.md) recovers original128/558-entry Mach/BSD tables, parallel original names and native indexing code; it now supplies the selected kernel targets without inventing nlist symbols. It also establishes kernel timeout narrowing, vector/descriptor preflight, result conversion and the common queue-receive connection.

| ID | Assumption and basis | Dependent result | Stress test / falsification probe | Status |
| --- | --- | --- | --- | --- |
| U1 | Available original cache represents a relevant library implementation; bytes, UUIDs and export metadata are checked | Cross-image API-to-trap path | Attest loaded image/slide and original runtime bindings; compare another build | Retained; runtime unverified |
| U2 | Standard ARM64 register, little-endian header and W-register rules apply | Packed fields and selector widths | Inspect original words, compile layout assertions and compare all-bit arithmetic | Confirmed for inspected static operations |
| U3 | The explicit runtime-global/TLS/callback/PAC models describe only their stated private fixtures | Wrapper continuation observations | Stop on unknown data/callback/code; compare actual initialization, ABI preservation and PAC separately | Retained; native reachability unknown |
| U4 | Pinned XNU header names explain numeric flags | MACH64 and option terminology | Original constants/branches and current SDK checks are independent; match exact target source before adopting broader policy | Retained; exact revision unknown |
| U5 | The supplied trace is complete for its recorded interval and matches its preserved hash | Packet pairing and bounded observation counts | Recheck raw lines/hex and event order; historical capture/producer attestation remains absent | Retained |
| U6 | Current RAX source explains the historical RESTART observations | Park/resume interpretation | Match historical producer executable/build and observe scheduler stages; source hashes/HEAD alone do not prove this | Retained; conditional interpretation |
| U7 | API/result models are adequate for local byte/register contracts, not successful messages/files | 32 finite fixtures | Vary flags, statuses, message shape and runtime table; retain unknowns and stop before every actual SVC | Retained |

No native target code, SVC, Mach/BSD operation, host callback, loader operation or RAX process was run. Original library instructions executed only in private Unicorn memory; SVC was intercepted before execution. Code pages were read-only/executable. Models explicitly seed callback-table versions, nullable logger, TLS, stack and trap results. Unknown libkernel callback state stops the close-error fixture.

## Layered call paths and emission sites

```text
daemon reply callback 0x100035184
  -> libSystem.B static reexport path
  -> mach_msg -> mach_msg_overwrite -> mach_msg2_internal
  -> svc #0x80, X16=-47

BootPolicy -> IOKit MIG stub -> mach_msg2_internal -> same Mach2 trap

daemon sidecar open/fstat/mmap/munmap/close
  -> libsystem_kernel wrappers -> BSD svc #0x80, X16 positive

kext RPC502/700 -> kernel MIG/RPC common transport
  (the kext path does not pass through these user-library veneers)
```

The [daemon callback report](daemon_receive_interface_report.md) establishes the reply call and its import slot `0x1010a1288`. The [mapping report](rpc502_mapping_report.md) establishes file/VM emissions and original imports. The [BootPolicy report](bootpolicy_backend_report.md) independently resolves IOKit's authenticated Mach2 stub; its native caller sites are `0x184e77c6c` and `0x184e78090`. Those are different layers from the final trap site.

| Available library interface | Raw veneer entry | SVC site | Signed X16 |
| --- | --- | --- | --- |
| open -> ___open | `0x180548678` | `0x18054867c` | 5 |
| close | `0x1805488dc` | `0x1805488e0` | 6 |
| mmap -> ___mmap | `0x180548a08` | `0x180548a0c` | 197 |
| munmap -> ___munmap | `0x18054b724` | `0x18054b728` | 73 |
| fstat, current ABI SYS_fstat64 | `0x180556434` | `0x180556438` | 339 |
| open$NOCANCEL raw veneer | `0x180548934` | `0x180548938` | 398 |
| close$NOCANCEL | `0x180549574` | `0x180549578` | 399 |
| mach_msg2_trap | `0x180547c18` | `0x180547c1c` | -47 |
| Legacy mach_msg_trap | `0x180547b58` | `0x180547b5c` | -31 |
| Legacy mach_msg_overwrite_trap | `0x180547b64` | `0x180547b68` | -32 |
| task_self_trap | `0x180547b40` | `0x180547b44` | -28 |
| mach_reply_port | `0x180547b28` | `0x180547b2c` | -26 |

Each retained veneer begins with MOV X16,constant then SVC #0x80. The current SDK ARM64 trap macro independently has this shape; the BSD constants are compile-checked. The ordinary cached mach_msg implementation calls Mach2 through `0x180550a24`; the existence of legacy veneers does not mean it uses them.

## Mach2 register packet and retry state

The API-level header is 24 bytes, with four-byte port-name/ID fields. The native wrapper loads header+8 as one little-endian qword, packs the other pairs, and invokes mach_msg2_internal with eight 64-bit arguments:

| Register | Low 32 bits | High 32 bits |
| --- | --- | --- |
| X2 | Header bits | Scalar send size, or send-vector count |
| X3 | Remote port name | Local port name |
| X4 | Voucher port name | Message ID bit pattern |
| X5 | Complex-body descriptor count | Receive port name |
| X6 | Scalar receive size, or receive-vector count | Priority bits from the sending legacy API's seventh scalar; zero on receive-only path |

| Register | Complete 64-bit value |
| --- | --- |
| X0 | Message pointer, or vector-array pointer |
| X1 | Option 64, including MACH64 class/vector bits; library interrupt bits are removed before the trap |
| X7 | Direct-interface timeout value; the legacy API supplies its u32 timeout |

Sign-extending the loaded signed message ID before shifting left32 preserves its original32-bit pattern. A full-domain proof checks the header-pair identities. A separate proof reduces the conditional CCMN/GT descriptor test to `SEND_MSG && (msgh_bits & 0x80000000)`: simple or receive-only messages supply descriptor count zero. This test concerns the header/body count; it does not validate descriptor contents.

The legacy wrapper first sign-extends its 32-bit options. With the inspected positive daemon reply options1/0x11, the default/empty voucher table adds MACH64_SEND_ANY (`0x800000000`). A runtime table of version at least 3 with a nonnull callback selects MACH64_SEND_MQ_CALL (`0x400000000`). The original data cell `__libkernel_voucher_functions` is at `0x1ed83e8d8`; its original v5 chain points to the 48-byte all-zero `__libkernel_voucher_functions_empty`. `___libkernel_voucher_init` at `0x180548154` replaces that cell from its first argument. Actual runtime table/version/callback values are unknown.

When the selected callback return is nonzero, native code builds two 24-byte vectors. The first contains the primary send/receive addresses and sizes. The second contains a 128-byte local context buffer, a null alternate receive pointer, callback-return-derived send size and receive capacity 128. The packet then carries vector counts 2 in X2.high 32 and X6.low 32; X5.low 32 still carries the ordinary complex descriptor count. The private nonzero probe uses callback return 5 solely to exercise this branch; it is not a valid-auxiliary-message claim. The inspected RAX implementation requires at least 8 bytes for nonempty auxiliary data. No callback data or kernel acceptance is established.

The wrapper's interrupt/retry rules are separate from RAX's scheduler restart:

| Event / original option | Native library action |
| --- | --- |
| Every initial trap | Remove MACH_SEND_INTERRUPT0x40 and MACH_RCV_INTERRUPT0x400 from kernel-facing options |
| MACH_SEND_INTERRUPTED0x10000007, caller send-interrupt bit clear | Retry with original packet and same timeout |
| Same status, caller bit set | Return the interruption |
| MACH_RCV_INTERRUPTED0x10004005, caller receive-interrupt bit clear | Retry receive; clear SEND_MSG, library interrupt bits and send-size/vector-count high half of X2 |
| Same receive retry after an original combined send+receive | Also clear MACH_RCV_SYNC_WAIT0x4000 |
| Same status, caller receive-interrupt bit set | Return the interruption |

Native receive retry zero-extends W26 into X26, preserving only X2.low 32. X0 and X3..X7 remain the original packet values in the retained cases, including the timeout value. Full-domain mask proofs establish the flag properties. Seven retry fixtures include send, receive, combined interruption and sync-wait variants; observed trap counts range 1..3. No finite native retry-duration bound is established. Wrapper retry work is O(R) time/O(1) state for R iterations, excluding kernel/callback execution.

For the recovered daemon reply callback, option 0x11 means SEND_MSG|SEND_TIMEOUT with timeout 0; option 1 means SEND_MSG. The callback's selected destroy results 0x10000003/0x10000004 are named MACH_SEND_INVALID_DEST/MACH_SEND_TIMED_OUT in the checked SDK. These API names clarify local handling; actual reply delivery and recipient port-object identity remain unverified.

## BSD wrapper, errno and runtime-hook contracts

At `0x180548960`, the mmap wrapper accepts its local preflight only when `length != 0 && (flags & 3) != 0`; it then forwards `flags | 0x40000`. The current SDK names 0x40000 MAP_UNIX03. Size 0 or neither mapping-kind bit selects EINVAL22 locally through cerror_nocancel, with no SVC. A full-domain proof covers all 64-bit lengths and32-bit flags for this local gate. Kernel checks remain separate. This refines the earlier daemon finding that size 0 reaches the mmap API boundary; it does not contradict it.

The open wrapper at `0x180553920` tests O_CREAT0x200. If clear, it passes mode zero to ___open. If set, it loads mode from the incoming caller-stack slot and masks it to16 bits. The private fixture seeds register X2=`0xdeadbeef` and stack mode=`0x123481a4`; the raw trap receives mode0 for O_RDONLY or0x81a4 for O_CREAT. This resolves why residual X2 at the daemon open emission is not a mode argument. The successful-open continuation also has a conditional system-version compatibility path controlled through the cell named `_system_version_compat_check_path_suffix`; its complete effect is outside this increment.

BSD veneers branch on carry after SVC. On the inspected error routes, cerror_nocancel at `0x1805485e0` writes the low 32 error to global `_errno` at `0x1ed83efa8` and, if nonnull, through the pointer loaded from TPIDRRO_EL0+8. It returns all-ones in X0 and X1. The public mmap wrapper may subsequently clobber X1; its API result is X0. Private error returns verify errno 12 for mmap and9 for fstat without host queries.

The ordinary open/close error veneer instead calls `_cerror` at `0x1805495cc`, which invokes a runtime function-table member before cerror_nocancel. `___libkernel_init` stores its first argument into `__libkernel_functions` at `0x1ed83e8f8`; `_cerror` uses member+0x28 with an authenticated call. The close-error fixture stops before reading an unmodeled table pointer. Native cancellation/signal semantics and initialization contents are not inferred from the helper name.

The exact exported `___syscall_logger` cell at `0x1eb065e48` is another runtime touch point. A nonnull value causes mmap to invoke it after the raw call and munmap to invoke it before the raw call. The callback receives `_mach_task_self_` as its second 32-bit argument, not a PID. In the private zero-task-name fixture, observed argument prefixes are `(0x90,0,length,0,mapping_result,0)` and `(0x20,0,address,length,0,0)`. The fixture stops at the logger call. Actual logging policy, callback behavior and task-port value remain unknown.

## Port-name publication and initialization context

Original nlist `_mach_init_doit`, range `0x18054dc3c`..`0x18054dce0`, establishes two publication edges:

| Operation | Call / SVC | Publication | Exact original cell |
| --- | --- | --- | --- |
| task_self_trap | Call `0x18054dc48`; SVC `0x180547b44` | STR W0 at `0x18054dc50` | `_mach_task_self_`, `0x1ed83e960` |
| mach_reply_port | Call `0x18054dc54`; SVC `0x180547b2c` | STR W0 at `0x18054dc5c` | `__task_reply_port`, `0x1ed83e8f4` |

These are 32-bit name stores, not kernel object pointers. No runtime name, right lifetime or correspondence to a FairPlay service port is established. The same initialization range reads page-configuration bytes through the commpage; the surrounding library initializer has source strings `vm_force_4k_pages`, `XBS_IS_CHROOTED` and `pfz`. This identifies further bootstrap/environment dependencies without assigning them to daemon RPC input.

The original IOKit reference previously recovered for BootPolicy, at `0x1e01c8b30`, resolves through a verified cache chain to this same `_mach_task_self_` cell. This joins its task-name input to the library initialization store. It does not equate that task port with the BootPolicy connection, bootstrap port or the kext's RPC destination.

The daemon's LC_BUILD_VERSION records platform 1, minimum 0x000d0000 and SDK 0x001b0000. This library records platform 1/platform 6 entries with minimum/SDK 0x001b0200. The original collection identifies Darwin27.2.0. These compile/source values do not establish which library or kernel the historical RAX capture used.

## Supplied trace: exact packet audit and parked-call interpretation

[Trace audit](triage_evidence/zut_trap_argument_audit.json) rechecks all 44 printed hex headers against the source file and reconciles all 27 printed Mach2 records. The trace SHA-256 remains `78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e`. For all 22 printed sends, the trap packet agrees exactly on header bits, send size, remote/local/voucher names, ID and descriptor count. Runtime receive arguments remain distinct fields rather than being inferred from the body.

All 27 records print PC=`0x180547c20`, which is RET immediately after this cache's Mach2 SVC. It is compatible with post-SVC PC logging, not the daemon's BLR/BLRAA call site. Current RAX captures the CPU's current PC for tracing, prints the handler result, then handles RESTART by backing the ARM64 PC up4 bytes.

| Printed send line | First trap / result | Host reply log | Repeated trap / result |
| --- | --- | --- | --- |
| 1500 | 1514 /0x80000001 | 1515 | 1526 /0 |
| 1541 | 1555 /0x80000001 | 1556 | 1567 /0 |
| 1575 | 1589 /0x80000001 | 1590 | 1601 /0 |
| 1609 | 1623 /0x80000001 | 1624 | 1635 /0 |
| 1643 | 1657 /0x80000001 | 1658 | 1669 /0 |

Each pair has identical eight arguments and no intervening second bridge-send log. In inspected RAX HEAD `4748a6ae8bd285369fe1413787b35587832f4dd3`, the four inspected source paths are clean; full file hashes and snippets are retained. `RESTART = i32::MIN + 1` has32-bit pattern0x80000001. The dispatcher prints it before restarting and does not install it as the normal guest return value. Message handling records Resume.step1 after sending, then filters out the send half when that same trap resumes. This provides a source-backed conditional explanation for the five duplicate observations, distinct from the library's native interruption retries. Historical executable/source identity is not attested, and RAX was not rerun or modified.

The 27 packet observations have17 KOBJECT-class packets (`0x200000000`) and10 MQ-class packets (`0x400000000`), including the five resumptions. These are trap observations, not27 established host sends. KOBJECT-only class bits are not produced by the ordinary cached mach_msg route described above under normal ABI preservation; direct Mach2 clients such as the recovered IOKit MIG stubs are a separate path. Exact historical caller attribution still requires resolved modules and LR/call edges. The trace continues to establish neither a selector26 transaction nor RPC502/700 traffic.

## Reproduction, bounded findings and quality gates

```sh
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_user_trap_interfaces.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/audit_zut_trap_arguments.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_user_trap_interfaces.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_user_trap_delivery.py
```

The [SDK probe](triage_evidence/user_trap_layouts.c) compiles Mach header/vector prefixes, scalar widths, API prototypes, BSD selectors, SVC immediate and flag/status constants. Pinned private MACH64 definitions come from the already retained [XNU header source](triage_evidence/xnu_osfmk_mach_message.h), with its original source/hash manifest; that source is not established as the exact target revision. Native bytes retain independent provenance. Extraction/audit complexity is O(B+E+H) time and O(B+E) retained space, with streamed source hashing and solver costs separate. Wrapper work is O(1) except retries/callbacks; native kernel costs are unknown.

| Impact | Bounded finding and next evidence |
| --- | --- |
| High | Packed header names and counts now connect observed trap fields to daemon/library APIs. Recover exact kernel syscall/trap dispatch and namespace conversion before assigning runtime port-object identity. |
| High | The repeated XPC packets have explicit pending/resume evidence, not a second printed send. Match the historical producer and scheduler state before treating trace rows as guest returns or duplicate IPC. |
| High | Runtime voucher tables can change class bits and vector layout; logger/runtime tables can add callbacks around BSD calls. Attest initialization and loaded bindings before treating default cache bytes as live state. |
| Medium | mmap API acceptance and kernel entry are separate: zero length reaches the daemon's API call but this library rejects it locally. Preserve that layer distinction in future boundary/error models. |
| Medium | open's variadic mode comes from the stack only with O_CREAT. Retain this ABI when correlating emulator register logs and wrappers. |
| Medium | Current task/reply names have exact initialization stores, but ownership and correspondence to service endpoints remain open. Follow initialization callers, thread reply-port management and actual runtime namespaces. |
| Low | Source build values and the static kernel version provide environment constraints without historical host attestation. Preserve source/runtime identity boundaries. |

QG1 factual technical scope. QG2 U1-U7 retain dependencies, basis, probes and status. QG3 this increment covers user-library trap/packet/port-publication, selected BSD/runtime hooks and trace resumption; the full interface objective remains active. QG4 register widths, endian pairing, scalar/vector extents, masks, compiled layouts and complexity are explicit. QG5 native versus synthetic versus historical-source evidence, callback-return 5 validity, API versus trap, and repeat observations versus sends are separated. QG6 original bytes/nlist/exports/fixups, source-file hashes, SDK, retained reference header, arithmetic proofs and trace hex are independent evidence classes. QG7 impact-bounded continuation leads are above. [Machine-readable checks](triage_evidence/user_trap_quality_gates.json) record the verified increment.
