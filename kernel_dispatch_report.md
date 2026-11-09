# Original kernel dispatch, Mach2 framing and native file/VM boundaries

The supplied kernel collection closes the static gap between the recovered user-library SVC veneers and concrete kernel handlers. Its original parallel name tables identify all 128 Mach entries and all 558 BSD entries. Native dispatch code indexes those tables, copies arguments, applies selected filter checks and converts results. The Mach2 handler reconstructs the packed header, validates scalar/vector framing, and orders send before receive. Its receive helper reaches the same common message-queue receive implementation already recovered beneath kext RPC transport.

This establishes a compatible static path across the supplied images. Actual runtime module selection, effective policy, port objects, native delivery and successful FairPlay processing remain unknown. Original kernel instructions ran only in private Unicorn fixtures, with explicit helper, state and PAC models. No native target, kernel operation, target host syscall, IPC, allocation or callback was executed; no IDB or original input was modified.

## Provenance and assumption register

Original collection: `/Users/___/Downloads/fpx/img4_dump/kernelcache.macho`, SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; kernel UUID `9b65bd6e-027b-34d1-a22b-ac03dccffc84`. Its `_version` identifies Darwin27.2.0, `xnu-13432.41.4~3/RELEASE_ARM64_T6041`. Addresses below are unslid. The [contracts](triage_evidence/kernel_dispatch_contracts.json) retain complete table bytes, original chained-pointer metadata and names, 40 LC_FUNCTION_STARTS-bounded ranges, native dispatch instruction checks and four solver proofs. All table handler/munger targets belong to original function starts. Pointer decoding requires membership in original format8 chains; a raw qword is not assumed to be a pointer.

The [95 private profiles](triage_evidence/kernel_dispatch_profiles.json) retain seeds, code-page hashes, helper interception records, PAC bypasses and stops. The [profile checks](triage_evidence/kernel_dispatch_profile_checks.json) distinguish arguments, saved user state, function return registers and modeled statuses. Code pages are RX; unmodeled code, data or system operations stop. Zero-filled boundary-stub pages are separately identified and contain no executed image instructions. Invalid-option guard effects, allocator behavior, namespace effects and successful message transfer are not modeled as native outcomes.

| ID | Assumption / basis | Dependent result | Stress test or falsification probe | Status |
| --- | --- | --- | --- | --- |
| K1 | Supplied collection is relevant to the daemon/kext; original SHA/UUID and earlier kext correspondence are checked | Cross-layer static dispatch path | Attest loaded kernel/cache/daemon slices, slides and bytes | Static identity confirmed; runtime pairing unknown |
| K2 | Original name-table indices describe adjacent dispatch entries; native index/stride loads independently select the tables | Handler naming and selected syscall/trap mapping | Recheck all pointer chains, function starts, strings, bounds and actual indexing instructions | Confirmed for original image; names are table identities, not invented nlist symbols |
| K3 | Standard AArch64 W-register, little-endian and saved-state rules explain inspected operations | Widths, sign extension, copied register records | Compare raw words, native loads/stores, all-bit proofs and varied fixtures | Confirmed for inspected operations |
| K4 | Private current-thread/task/space/map/filter/canary/PAC seeds describe only the stated fixture | Local execution and boundary arguments | Stop on unknown code/data; vary branch inputs; independently attest live object provenance/PAC and policy | Retained; native reachability unknown |
| K5 | Pinned public XNU source supplies conventional terminology | Semantic names for stripped helpers, flags and return tags | Compare original constants/fields/callers; recover exact target revision before extending source semantics | Retained; concrete reference drift documented below |
| K6 | Modeled send/receive success and returning guard callbacks are control-flow probes | Ordering and packet reconstruction | Observe actual helper effects, guard disposition, namespace/queue state and native transaction | Retained; no successful native send/receive established |
| K7 | Selected scalar/vector/compatibility cases and explicit formulas cover the stated increment | Finite profile conclusions and arithmetic proofs | Vary missing modes, runtime initialization, callback policy, allocation and lifecycle paths | Retained; full interface goal remains active |

The public [Mach table definition](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/syscall_sw.h#L74), [BSD entry definition](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/sysent.h#L39) and [reference inventory](triage_evidence/kernel_dispatch_references.json) are version-pinned comparisons. The target's exact source revision is unknown. Comparing all128 Mach entries against that reference exposes two differences:

| Mach index | Original collection | Pinned public reference | Implication |
| --- | --- | --- | --- |
| 63 | `mach_vm_reclaim_update_kernel_accounting_trap`, argc3/u32 words5 | Same name, argc2/u32 words2 | Reference prototype cannot replace original argument metadata |
| 108 | `thread_set_x86_64_compat_trap`, argc1/u32 words1 | `kern_invalid`, argc0/u32 words0 | Reference does not enumerate the target's entire implemented trap surface |

## Dispatch and names

```text
daemon / cache library
  -> SVC #0x80, X16 selector
  -> exception-handler sign test 0xfffffe000be7cb68
       |
       +-- nonnegative -> BSD dispatcher 0xfffffe000c43ba9c
       |                  -> sysent[index], stride24
       |                  -> handler(proc, args, rval)
       |                  -> saved result / carry conversion
       |
       +-- negative -> special negative-selector cases
                       -> Mach dispatcher 0xfffffe000be76b10
                       -> mach_table[-signed32(selector)], stride24
                       -> handler(copied argument record)

Mach2 handler -> send helper -> deeper copyin/queue/kobject facilities
             -> receive helper -> common queue receive -> user copyout

kext RPC     -> kernel RPC helper -> common queue receive
```

The containing exception-handler range is `0xfffffe000be7c764..0xfffffe000be7d570`. It loads saved selector W27 at state+0x88, handles `INT32_MIN` separately, tests its sign, and emits BL at `...be7cb8c` to the BSD dispatcher or `...be7d02c` to the Mach dispatcher. Negative selectors -3/-4/-5 have separate branches before ordinary Mach dispatch. This is the recovered SVC-handling path within a larger exception handler; complete vector entry, ESR decoding and return-to-user validation are not established by this increment.

| Original data | Address | Entries | Entry bytes | Native consumer |
| --- | --- | --- | --- | --- |
| Mach dispatch | `0xfffffe0007efb010` | 128 | 24 | `...be76b70..be76b94` computes index*24 and loads handler+8 |
| Mach names | `0xfffffe0007efbc10` | 128 | 8 | Parallel original C-string pointers; whole table retained |
| BSD dispatch | `0xfffffe0007f2ca58` | 558 | 24 | `...c43bbac..c43bbc8` bounds/selects/indexes entry |
| BSD names | `0xfffffe000caa30c8` | 558 | 8 | Parallel original C-string pointers; selected names match original library selectors |

The Mach record contains u8 argc at+0, u8 32-bit-word count at+1, u8 returns-port at+2, handler pointer+8 and compatibility-munger pointer+16. BSD records contain handler+0, munger+8, signed32 return-type tag+16, signed16 argc+20 and u16 32-bit argument extent+22. These are target layouts, corroborated by native field loads.

| Signed X16 | Original Mach name | Handler | argc / u32 words | returns-port |
| --- | --- | --- | --- | --- |
| -26 | mach_reply_port | `0xfffffe000bcf8c0c` | 0 / 0 | 1 |
| -28 | task_self_trap | `0xfffffe000bcf89e0` | 0 / 0 | 1 |
| -31 | mach_msg_trap | `0xfffffe000bcdd730` | 7 / 7 | 0 |
| -32 | mach_msg_overwrite_trap | `0xfffffe000bcdd148` | 8 / 8 | 0 |
| -47 | mach_msg2_trap | `0xfffffe000bcdd73c` | 8 / 16 | 0 |
| -50 | thread_get_special_reply_port | `0xfffffe000bcf8ca0` | 0 / 0 | 1 |
| -100 | iokit_user_client_trap | `0xfffffe000c572744` | 8 / 8 | 0 |

The legacy -31 handler zeroes argument-record+0x38 then tail-branches to -32's handler. Its seven-argument interface and -32's eight-argument trap record are distinct from the nine-argument user mach_msg_overwrite API recovered in [user_trap_interface_report.md](user_trap_interface_report.md). The current ordinary cached mach_msg path uses -47. Trap -100 is also distinct from IOKit MIG message IDs2862/2865; its presence is not evidence that FairPlay invokes it.

Mach dispatch reads saved selector low32 and negates signed32 to form its index. For a valid negative selector in -127..-1, it selects the original table; selector<=-128 and entries pointing to `kern_invalid` take the exception boundary at `...be76d58`. The dispatcher copies argc*8 bytes from saved state+8 into its local argument record on the inspected64-bit path, checks argc<10, then calls through the original handler at `...be76c88` with PAC discriminator0x307a. The32-bit path uses the separately recorded u32 count and munger, discriminator0x2abe. Its full compatibility behavior is retained statically; the fixture set focuses on64-bit Mach dispatch.

A nullable per-task Mach filter mask is checked before handler dispatch. For a clear bit and nonnull callback cell `0xfffffe0007ef8008`, the callback receives a process-associated pointer and positive Mach index. Zero callback status continues. Nonzero status skips the handler: returns-port entries produce zero, other entries retain the status (`...be76d04..d0c`). With no callback, the inspected clear-mask path continues. After dispatch, saved64-bit X0 receives sign-extension of W21 at `...be76cac..cb0`; this must be distinguished from the C function's own return register after later housekeeping. The fixture status0x8000000e becomes saved X0=`0xffffffff8000000e`.

## BSD file/VM ABI and result conversion

| X16 | Original name | Handler | argc / u32 argument bytes | Return tag |
| --- | --- | --- | --- | --- |
| 5 | open | `0xfffffe000bf56440` | 3 / 12 | 1, signed int |
| 6 | close | `0xfffffe000c289ad8` | 1 / 4 | 1 |
| 73 | munmap | `0xfffffe000c2b5ae8` | 2 / 8 | 1 |
| 197 | mmap | `0xfffffe000c2b4c64` | 6 / 28 | 4, address |
| 339 | fstat64 | `0xfffffe000c28a51c` | 2 / 8 | 1 |
| 398 | open_nocancel | `0xfffffe000bf565b0` | 3 / 12 | 1 |
| 399 | close_nocancel | `0xfffffe000c289d4c` | 1 / 4 | 1 |

These names come from the original collection, independently agreeing with the pinned [syscalls.master](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/syscalls.master). The dispatcher selects low16 of the saved code. Values>=558 select index63, whose original name is `#63` and handler is `0xfffffe000c300d1c`. A full-domain proof verifies the bounded selection and24-byte stride. X16=0 selects an indirect interface: the code comes from saved X0 and arguments begin with saved X1. Thus a forced direct BSD-dispatch fixture for code0x10005 selects index5; this is a local selector rule, not a bypass of the outer sign/special-case path.

For64-bit direct calls, argc*8 bytes are copied into thread+0x5c0. At `...c43bd50..bd60`, native handler arguments are `(proc, thread+0x5c0, thread+0x600)`. The last pointer is the two-word BSD result record. The native call uses PAC discriminator0xbcad. A per-process mask may invoke the separate policy helper at `...c43be4c`; successful mask/policy admission remains distinct from handler authorization and file permissions.

An indirect compatibility branch checks task+0x6c8 bit2. When clear, mmap's original munger `0xfffffe000bf08c94` expands the first five u32 values into u64 slots and copies a64-bit off_t from packed offset20 to slot40. When set, the inspected64-bit record is left intact. Both branches execute original instructions in private fixtures. The [reference argument collector](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/dev/arm/systemcalls.c#L372) explains the arm64_32 vararg role; actual task mode is unknown.

Return converter `0xfffffe000c43be88` supplies the other side of the [library error veneers](user_trap_interface_report.md):

| Handler status / return tag | Saved64-bit state |
| --- | --- |
| status0, tag1 | Sign-extend each of the two signed32 result words into X0/X1 |
| status0, tag2 | Zero-extend each of the two u32 words into X0/X1 |
| status0, tags3..7 | Copy full64-bit result to X0; X1=0 |
| status0, tag0 | Preserve saved registers on the inspected64-bit branch |
| Ordinary nonzero status | X0=sign-extended status; X1=0; set saved CPSR carry bit29 |
| status-2 | Preserve saved result/state in this converter |
| status-1 | Enter saved-state authentication, then statically decrement saved PC by4 and re-sign it |

The dispatcher clears carry before calling the handler. The private converter fixtures start with explicit CPSR seeds; they do not claim that success independently clears carry. The -1 fixture stops at the authentication helper, before privileged state manipulation. Native BSD restart, native library Mach interruption retries, and RAX's internal0x80000001 scheduler marker are three separate mechanisms.

The original close and close_nocancel entries converge on `0xfffffe000c289b50`. The cancelable wrapper additionally clears thread+0x6b0 bit2 and checks `(old_flags & 0x38)==8`, taking a status4 return path. Open/open_nocancel both call `0xfffffe000bf55720`, with different surrounding cancellation handling. These are code/call correspondences; full file-description, reference-count and cancellation semantics remain open. The fstat64 entry tail-calls `0xfffffe000c289dbc` with the supplied fd/buffer and final W5=1, distinct from inferring a struct layout from the symbol alone.

## Mach2 policy, framing and ordering

The kernel receives one pointer to eight copied64-bit trap arguments. Its original loads corroborate the [user packet map](user_trap_interface_report.md). At `...bcdd984..d99c`, the handler builds a separate send context: low32 header bits at+0, header size initially0 at+4, remote/local names+8/+12, voucher/ID+16/+20 and descriptor count+24. Message/auxiliary addresses occupy+32/+40, and u32 extents+48/+52. Header fields arrive from the packed registers, before deeper payload copyin.

The trap reads timeout with LDR W at argument-record+0x38 (`...bcdd784`), so direct X7's upper32 bits are discarded. The private packet `0x11223344aabbccdd` supplies timeout `0xaabbccdd` to both downstream helpers. Priority comes from packed X6.high32. This narrows the direct library's64-bit transport value without assigning units beyond the conventional mach_msg_timeout_t interpretation; no elapsed-time behavior was measured.

The user option mask is `0x0000001f0fb6dbbf`, with user bit16 additionally inspected and converted into internal bit38. Native code removes the user bit16 and inserts bit38 when it was set; bits6/10 (library interruption controls) do not survive. Task read-only flags bit14 contributes internal bit39. IPC-space field+0x58 contributes a value shifted40, through authenticated field loads. The handler adds internal bit63 before deeper message calls. Private original-instruction probes verify that forged user internal flags are removed and that explicit task/space seeds insert their respective bits. Effective live policy is unknown.

The pinned [policy implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_policy.c#L176) supplies the conventional FILTER_NON_FATAL/FILTER_MSG/space-policy labels. For sending, class bits33..36 must contain exactly one set bit; vector sends additionally require MQ_CALL or SEND_ANY. A full-domain proof reduces the original CMP/CCMP/LS predicate to that rule. Invalid options invoke the guard-policy helper `0xfffffe000c629ba0` and then construct status0x10000013 if it returns. The fixtures model that guard as returning; actual exception/termination disposition remains unknown. No invalid-option error is claimed to have reached a live process.

| Boundary | Native check / action | Local outcome before deeper operation |
| --- | --- | --- |
| Vector count | max(send count,receive count), taken unconditionally from packed u32 fields, must be1..2 | Copies24 or48 bytes with exact `_copyin` at `...bcdd8a4` |
| Count0 / count>2 / copyin failure | Separate count and copyin branches | Send:0x10000008 for count0,0x10000002 otherwise; receive-only:0x10004013 |
| Vector primary send | Nonzero data pointer; size>=24; size multiple4; size<=0x2ffffbc | Rejects before send helper when inconsistent |
| Optional auxiliary send, count2 | Size0 allowed; nonzero requires data pointer and8..1024 bytes | Sizes5/7 ->0x10000018;1025 ->0x10000019 in original-instruction fixtures |
| Scalar/send-context framing | Same size/alignment/maximum checks in `0xfffffe000bcdd350` | Maximum is50331580 bytes; reaching allocator is not successful allocation/send |
| Complex message | Size>=28 and descriptor count<=floor((size-28)/12) | Coarse minimum-descriptor-extent check; descriptor types/content remain deeper checks |
| Noncomplex message | Descriptor count must be0 | Nonzero count selects0x1000000e |
| Auxiliary receive, count2 | Prefer alternate receive address when nonzero, otherwise primary; resulting address nonzero and capacity>=8 | Invalid auxiliary receive args select0x10004013 before queue receive |
| Send then receive | Send status tested before receive-side validation | Nonzero send status skips receive; modeled success can precede receive-argument rejection |

The minimum-descriptor quotient uses UMULH with `0xaaaaaaaaaaaaaaab`, then LSR3. A bounded-integer proof establishes equality to division by12 for every unsigned32 size>=28; the128-bit product cannot overflow in that domain. This is a minimum possible descriptor size, not a claim that every descriptor is12 bytes. Original kernel/user OOL descriptor widths remain as established in [kernel_user_copyout_report.md](kernel_user_copyout_report.md).

Receive primary-buffer size/address are not given the send preflight tests in this handler. Their consequences belong to receive/copyout and framework handling. Send-only vector calls still undergo the initial max(send count,receive count) check: unused receive-count garbage can reject the vector-array copy before send. Conversely, after a valid array copy, receive-specific auxiliary checks are deliberately later. The fixture with one send vector, two receive vectors and receive auxiliary capacity7 reaches the modeled send helper before returning receive status0x10004013. It does not prove a real message was sent.

## Receive namespaces, thread slots and publication

| Kernel receive-helper argument | Meaning from native use / reference correlation |
| --- | --- |
| X0 / X1 | Primary / auxiliary user receive addresses |
| X2 | Effective options, including internal Mach2/policy flags |
| W3 | Truncated timeout |
| W4 | Sync boosting name: packed remote name if SYNC_WAIT bit14, otherwise0 |
| W5 / W6 | Primary / auxiliary receive capacities |
| X7, consumed as name | Packed receive port name |

For scalar receive, X5 can retain the packed priority in its upper32 bits; the callee stores W5. The fixture records X5=`0x5500000200` while the effective primary capacity is512 bytes. A function's u32 argument must therefore be read at its consumed width; zeroed upper register bits are not implied by a C type.

Receive helper `0xfffffe000bcdd4e4` calls `0xfffffe000bcc8cf4` with current IPC space, receive name and an output-object pointer at `...bcdd564`. Only status0 continues. The returned receive object goes into thread+0x398. Native code stores primary address+0x378, optional auxiliary address+0x380, capacities+0x388/+0x38c and effective options+0x390. At `...bcdd6d0` it calls common receive `0xfffffe000bcc83b4` with the receive object's+0x10 queue and timeout. Its successful continuation tail-branches at `...bcdd708` to `0xfffffe000bcdcc7c`, the previously recovered user receive-results/copyout range.

This joins the new trap path to [normal namespace/OOL copyout](kernel_user_copyout_report.md) and the [kext's kernel RPC transport](kernel_rpc_transport_report.md), while preserving different callers, namespaces and result handling:

```text
user Mach2 receive name
  -> current-space name/object helper
  -> thread user-receive state
  -> common queue receive 0xfffffe000bcc83b4
  -> user receive results / namespace and VM copyout

kext kernel RPC
  -> kernel reply endpoint and kernel-specific transport state
  -> common queue receive 0xfffffe000bcc83b4
  -> kernel RPC reply handling
```

SYNC_WAIT additionally compares the returned receive object against the authenticated pointer at thread+0x450, then may resolve the boosting name and call special-reply linkage `0xfffffe000bccef30`. An incompatible receive-object path selects0x10004007 after releasing the retained receive object. Full linkage, locking and namespace rights remain deeper requirements.

| Endpoint storage | Coordinate | Established distinction |
| --- | --- | --- |
| Kernel RPC caller's reply endpoint | thread+0x3f0 in earlier transport report | Kernel-side reply object used by the recovered kext RPC helper |
| User receive sync-reply comparison | thread+0x450 in this helper | Separate authenticated thread field; equality required on selected SYNC_WAIT path |
| Library task reply name | `0x1ed83e8f4`, store at `0x18054dc5c` | u32 namespace name obtained through ordinary mach_reply_port trap |
| Library task-self name | `0x1ed83e960`, store at `0x18054dc50` | u32 task name obtained through task_self_trap |
| Kext destination context | context+0x18 | Acquired kernel destination object; no equality with the above user names established |

The task-self handler's inspected copyout call at `...bcf8b0c` supplies `(space,send-right-object,17,2,0,&u32name)` to `0xfffffe000bcc9c1c`. Zero status reads the resulting name; status20 selects name0xffffffff; other nonzero status selects0. Null/dead sentinel handling precedes that call. The original mach_reply_port handler calls `0xfffffe000bccd000` at `...bcf8c60` with `(space,0x101,0,0,&name,&object)`; on success it unlocks the returned object and returns the name. Full allocation/copyout policy and lifetime remain open. These are namespace-conversion/allocation sites, not known runtime port numbers.

## Native munmap preflight and page geometry

The munmap handler reads its VM map from thread+0x428 and page shift from map+0x2c, with a null-map fallback14. For the inspected native branch, address must be page-aligned and length nonzero. It rejects overflow of address+length, rounds the end upward with the map mask, and requires the rounded end to exceed the start. The native call at `...c2b5b80` supplies `(map,base,rounded_extent)` to `0xfffffe000bdc1ec0`; a nonzero callee status becomes EINVAL22 in this wrapper. The deeper deallocator's complete semantics are not recovered here.

With the explicit fixture page shift14, page size is `2^14=16384` bytes. Address0 and length1 reach the VM boundary as `(map,0,16384)`; address65536/length1 or16384 reach `(map,65536,16384)`. Address65537, zero length, address+length overflow and final round-up wrap return22 before the VM operation. Address0 passing this preflight does not establish that it is mapped or deallocated successfully. These tests refine the [sidecar cleanup boundary](rpc502_mapping_report.md); they do not establish that every descriptor/map has been retired.

## Bounded findings and continuation

| Impact | Finding / unresolved boundary | Concrete next evidence |
| --- | --- | --- |
| High | Static user SVC-to-kernel dispatch gap is closed for the supplied builds; runtime binding remains unknown | Match loaded modules/slides and effective task mode, then trace actual receive names through namespace entries to kernel objects |
| High | Send can precede receive-specific rejection; native Mach retries and RAX resumptions have different stages | Correlate packet identity, send/dequeue events, statuses and installed CF retry/cleanup; avoid inferring send count from trap-return count |
| High | Thread+0x3f0, thread+0x450, task reply name and kext destination are distinct accounting scopes | Recover creation, bind/unbind, lookup, replacement, reference transfers and final destruction for each endpoint |
| High | Original dispatch entries differ from the public reference | Locate exact target revision or continue native recovery; include original tables in any ABI/model work |
| Medium | Runtime task/space policy can alter effective flags before port/queue policy is reached | Recover setters, filter callbacks and inherited policy; distinguish a class preflight from entitlement/receiver authorization |
| Medium | Compatibility mungers, timeout narrowing and nonzero upper register bits affect ABI interpretation | Add32-bit/arm64_32 native-state fixtures and exact callback prototypes; retain W/X consumed widths in emulator comparisons |
| Medium | Body/descriptor checks are only initial framing limits | Follow allocator, descriptor-kind validation, copyin rights/OOL, kobject admission, body errors and failure cleanup |
| Medium | Native munmap may fail before or after a page-rounded VM call | Complete sidecar mapping/free/unmap/close aliases and VM-map entry semantics; do not equate a library call or cleared fd with resource retirement |
| Low | Raw IOKit trap100 exists alongside IOKit MIG calls | Identify actual callers before extending the FairPlay interface inventory |

## Reproduction and quality gates

```text
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_kernel_dispatch.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_kernel_dispatch_delivery.py
```

The first command executes only selected original instructions in private memory. The second re-extracts tables/ranges, checks four solver results, verifies source-hashed profiles and explicit expectations, checks report links/JSON, preserves the three original analysis inputs and refreshes the owned manifest. Table extraction/validation is O(B+F+T+I) time and space for image bytes, fixups, table rows and retained instructions. Each fixture has a20000-instruction cap and finite explicitly mapped storage; solver complexity is separate. The scripts use the supplied paths and fail if identities/layouts differ.

The [quality-gate record](triage_evidence/kernel_dispatch_quality_gates.json) scopes QG1-QG7 to this increment. The assumption register, original/reference differences, native/model boundaries, numeric widths and continuation table resolve the increment's interpretation limits. The full investigation remains active and incomplete.

## Subsequent namespace and reply-reference recovery (2026-11-01)

[kernel_namespace_report.md](kernel_namespace_report.md) extends receive-name resolution through original encoded-table decoding,24-byte entries, object locking and post-lock identity/generation/rights validation. Receive lookup adds an object reference before unlocking; receive-results decrements it at0xfffffe000bcdce04. Generic translation instead returns a locked object without that additional retain. User/kernel reply bindings, destination link holds, turnstile holds and selected unlink/reset transitions now have separate native contracts. Complete namespace writers, actual endpoints, locking/PAC, destruction and native delivery remain open.
