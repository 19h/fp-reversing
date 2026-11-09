# Matching kernel RPC transport: reply ports, ownership and descriptor PAC

The matching kernel transport supplies the reply endpoint that the kext's null `mig_get_reply_port` result leaves unspecified. Native code obtains it from the current thread at offset `0x3f0`, creates/binds it when absent, inserts it in the internal outgoing message and waits on it. This is distinct from the destination acquired by the protected FairPlay dispatcher.

The same transport implements a further ABI boundary: the kext-policy path accepts unsigned descriptor pointers, signs them in internal message storage, authenticates them on return and writes unsigned pointers into the kext's reply buffer. Both FairPlay clients pass a receive capacity of **400 bytes**, accommodating the normal **392-byte** kernel reply and **8-byte** minimal trailer.

## Provenance and assumption register

Analysis date: 2026-11-01. Static addresses are unslid. The original kernel collection is `/Users/___/Downloads/fpx/img4_dump/kernelcache.macho`, SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, kernel UUID `9b65bd6e-027b-34d1-a22b-ac03dccffc84`. Prior [collection identity evidence](kernel_port_resolution_report.md) relates the extracted kext and the currently reported running build to this collection; it does not attest live memory or the historical zut environment.

[Native ranges and proofs](triage_evidence/kernel_rpc_transport_contracts.json) retain 15 complete `LC_FUNCTION_STARTS`-bounded ranges, original bytes/hashes, 88 direct call/tail edges, exact symbol matches separately from inferred roles, 23 instruction checks and two full-domain SMT results. The original kernel contains 23,033 function starts. These boundaries are compiler metadata, not a claim that every range corresponds to a named public source function.

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| R1: the supplied collection and extracted kext are the intended build | Static target identity, function bounds and client capacities | Recheck hashes, UUIDs, section/fixup correspondence and original range bytes. Runtime mutation remains a separate observation. |
| R2: ordinary current-thread, port, message and callee-preservation contracts hold | Field identities, normal receive loop and reference tracking | Trace field writers, locking and callees; observe registers/objects in a native transaction. A nonzero/non-dead pointer test alone does not validate an object. |
| R3: pinned public XNU functions explain the stripped helpers with matching native shape | Descriptive helper names, field names and right-type interpretation | Match the exact target source or independently recover each callee. Stripped helper roles below remain source-correlated, not exact nlist names. |
| R4: messages contain supported descriptor types and valid pointer/PAC inputs | Normal descriptor signing/stripping and VM-copy forwarding | Exercise invalid tags, wrong address modifiers, null pointers and stale copy objects. Captured instructions do not establish successful runtime authentication. |
| R5: successful incoming reply follows the observed size and trailer contract | Normal 400-byte delivery and 8-byte trailer | Inspect the actual reply, initialized trailer and all copy paths. The proof bounds copied extent, not the validity of every copied byte. |

No target code was executed and no IDB was modified. These original collection bytes need no live IDA database containing the kernel. The existing kext/daemon IDBs are not treated as a kernel implementation oracle.

## Wrapper and transport boundary

| Entry / role | Static range or site | Established native contract |
| --- | --- | --- |
| Exact `_mach_msg_rpc_from_kernel_proper` | `0xfffffe000bcf5e28`-`0xfffffe000bcf5e3c` | X0=message, W1=send bytes, W2=receive capacity; sets W3=1, X4=`0x2000000000`, X5=0; tail-branches to common transport |
| Common transport, stripped name | `0xfffffe000bcf59e0`-`0xfffffe000bcf5e28` | Receives the six arguments above; reads current thread using `MRS TPIDR_EL1` |
| Exact `_mig_get_reply_port` | `0xfffffe000bcf5f18`-`...5f24` | Returns X0=0 |
| Exact `_mig_dealloc_reply_port` | `0xfffffe000bcf5f24`-`...5f2c` | BTI/RET; no teardown operation |
| Exact `_mig_put_reply_port` | `0xfffffe000bcf5f2c`-`...5f34` | BTI/RET; no recycling operation |
| RPC502 call | `0xfffffe000a5a20f8` | Send 88 bytes; receive capacity 400 bytes |
| RPC700 call | `0xfffffe000a5a2368` | Same send/receive sizes; receiver remains unknown |

The wrapper's policy value is bit 37. W3=1 makes the inspected receive path interruptible. X5=0 means no `message_moved` output is requested by these kext clients; the common helper nevertheless contains writes of 0 before preparation and 1 after successful internal copyin when that optional pointer is nonnull.

At `...bcf5a14`-`...5a2c`, the common helper rejects a destination whose pointer bits are 0 or all-ones, returning `0x10000003`. It calls the message-copy helper at `...5a48` and propagates its nonzero result. This pointer-bit predicate is not an active-port, service-identity or access-policy check. The [pinned RPC source](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/ipc_mig.c#L347) supplies descriptive names; native behavior is retained independently.

## Reply endpoint creation, binding, reuse and teardown

```text
current thread = TPIDR_EL1
          |
          +-- [thread+0x3f0] nonzero ---- reuse existing port
          |
          +-- zero --> helper 0xfffffe000bcf8e14
                         allocate / initialize port
                         increment object reference
                         [thread+0x3f0] = port
                         [port+0x40] = signed owner-thread pointer
                         unlock and drop allocation reference
          |
internal outgoing header.local = port
          |
copyin local disposition 21 -> send-once right
          |
send request -> link reply port to destination -> receive
          |
success: preserve bound thread reply port for reuse
interruption/termination route: clear thread field and teardown port
```

The creation helper is `0xfffffe000bcf8e14`-`...8f38`; the common transport calls it at `...bcf5aa8` only after a null thread field. The helper itself also contains an old-binding cleanup branch for valid existing pointers. On its normal new-binding path, it increments `[port+4]` at `...8eac`, stores the thread field at `...8ec4`, signs/stores the owner thread at port+`0x40`, then decrements the object reference at `...8ef0`. No absolute reference-count value is inferred without the initializer's complete contract.

The teardown helper `0xfffffe000bcf837c`-`...83d0` reads the field, locks the port through a callee, clears `[thread+0x3f0]` at `...839c`, invokes the unlink/adjust helper with third argument 4, locks again and tail-calls `0xfffffe000bccdbb4`. The [pinned thread-IPC source](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/ipc_tt.c#L1386) correlates these roles with kernel-special-reply-port binding and destruction. Full native port-destruction internals remain outstanding.

The normal RPC return does not clear this field. Therefore this receive endpoint has thread lifetime/reuse behavior rather than the stub-local lifetime implied by interpreting `mig_put_reply_port` as an active recycler. Neither its actual runtime pointer nor a daemon-local numeric name was observed.

## Separate destination and reply-right accounting

| Resource | Native evidence | Ownership implication within the inspected transport |
| --- | --- | --- |
| FairPlay acquired destination send reference | Protected scratch+`0x18`; prior [local release recovery](kext_port_vm_report.md) | A caller-owned reference remains a separate accounting obligation |
| Message destination COPY_SEND | Common copyin call at `...bcf5b40`; disposition 19 reaches `0xfffffe000bcc9718` | Branch `...bcc9890` increments destination+`0x88` and object+4; a message-owned send reference is created under the declared port contract |
| Temporary destination-object retain | `...bcf5b7c`-`...5b98` | Atomically increments destination+4 after copyin, before send; this does not increment destination+`0x88` |
| Reply MAKE_SEND_ONCE | Common stores reply at internal header+`0x10`; ORs local disposition 21 | Copyin calls helper `0xfffffe000bcd0628`, which increments reply+`0x8c` and object+4 on the active-port branch |
| Bound reply receive endpoint | Current-thread+`0x3f0`, owner-thread field and teardown helper | Persists across normal RPC completion; exceptional paths can unbind/destroy it |

The exact original disposition table at `0xfffffe0007010ab0` maps inputs 16..21 to `(16,17,18,17,17,18)`. Thus these normal COPY_SEND and MAKE_SEND_ONCE dispositions become internal send and send-once types 17 and 18. Their numeric semantics are source-correlated; the table and increments are native facts.

The common transport sends at `0xfffffe000bcf5ba8`, passing `(kmsg,0x10001,0)` to `0xfffffe000bcc7040`. On send failure it drops its temporary object reference and destroys the message at `...5bd4`, passing flags0. On receive success it drops the same temporary reference at `...5ce4`. The helper `0xfffffe000bcc9240` atomically decrements object+4 and enters last-reference cleanup when appropriate. These temporary-reference releases must not be substituted for the protected caller's `_ipc_port_release_send`: the native counters and ownership scopes differ.

Voucher handling is another distinct resource: the transport optionally obtains/converts a current-thread/default voucher, stores an authenticated pointer at kmsg+`0x10`, and adds voucher disposition 17. On internal copyin failure it clears that slot/flags, calls exact `_ipc_port_release_send` at `...5cac`, then frees the message container. Successful sends transfer this voucher with the message. This does not establish the daemon's authorization policy.

## Wait, interrupt and reply validation contracts

The receive loop starts at `0xfffffe000bcf5bec`. It checks the reply-port active bits, links reply and destination through the call at `...5c14`, clears the thread receive state, writes receive-size bits `0xffffffff` at thread+`0x388`, and calls `0xfffffe000bcc83b4` at `...5c44` with `(reply+0x10,0,1,current_thread,0)` for this wrapper. The second argument 0 is a native timeout argument, not evidence of a zero-duration polling request; no timeout option is set in the observed RPC path.

After receive, status is loaded from thread+`0x3a0` and the authenticated returned message pointer from+`0x3b8`; completion processing is called at `...5c70`. Status 0 proceeds to reply conversion. A nonzero result tests thread+`0x43c` bit5: clear retries the loop; set releases the destination retain, tears down the thread reply port and returns that status. The source contract expects interruption, but the inspected native nonzero branch does not explicitly compare against a single error value.

Before waiting, the interruptible path also checks thread+`0x43b` mask `0x11`; zero selects destination-release and reply-port teardown and returns `0x10004005`. Active reply-port validation and internal size-overflow checks have panic/trap continuations; they are not ordinary transport-error returns.

Let S be the reply's u32 inline size and C the caller's u32 receive capacity, both in bytes. Native `...5d48` first checks overflow of S+68, entering a panic path if it overflows. For non-overflowing S:

```text
C < S          -> destroy reply, return 0x10004004
S <= C < S+8   -> copy S bytes
S+8 <= C < S+68 -> copy S+8 bytes
C >= S+68      -> set trailer extent=68; copy S+68 bytes
```

The middle case relies on an already initialized minimal trailer; the native code does not rewrite its extent there. Two SMT queries establish the pointer-bit predicate equivalence and `S <= copied_extent <= C` over the stated complete bit-vector domains. They do not establish message/trailer initialization, pointer validity or successful native execution.

For the normal FairPlay response S=392 bytes and C=400 bytes, the third case copies 400 bytes with an 8-byte trailer. This receive capacity is distinct from the 392-byte inline ABI and from the daemon's 384-byte user message. The kernel-side trailer appended here is also distinct from the daemon request trailer that its MIG stub inspects for audit data; this finding does not close that earlier receive-allocation/trailer gap.

The common transport does not check the FairPlay reply ID, OOL count or repeated extents in this local range. Those remain generated-client validation duties. Reply destination/header conversion is performed by `0xfffffe000bcc6154`, called at `...5d7c`, before final copyback at `...5dc0`; it consumes the incoming destination representation, swaps header roles, and cleans any voucher send reference. Complete receiver-side user namespace conversion remains a deeper boundary.

The following role mapping joins the recovered kext transport and [daemon generated-reply behavior](daemon_receive_interface_report.md). It describes a compatible normal RPC502 chain under R1-R5, not an observed end-to-end exchange. User/kernel namespace conversion between these stages remains separately unproved against the complete matching native receive implementation.

| Message stage | `remote` field | `local` field |
| --- | --- | --- |
| Kext request before transport | Daemon destination object, kernel+8 | NULL, kernel+`0x10` |
| Internal request after transport setup | Daemon destination object | Thread reply-port object; MAKE_SEND_ONCE disposition |
| Daemon received request | Task-local name for reply send-once right, user+8 | Service receive name, user+`0x0c` |
| Daemon generated reply | Copies received request's remote name | Zero |
| Kernel internal reply before destination conversion | Destination is the thread reply endpoint | Zero for this generated reply |
| Kext reply after destination conversion | Previous internal local value, therefore zero here | Converted destination name/sentinel, not the daemon service object |

This separates the receiving service passed to daemon application code from the destination used to send its reply. It also explains why the kext's generated reply validator can require a null remote field after conversion without implying that no reply right was used during transport.

## Kext-policy descriptor-pointer ABI

| Event | Native sites | Pointer representation |
| --- | --- | --- |
| Kext supplies request | Prior client descriptor+`0x24` | Unsigned `vm_map_copy_t` under the recovered constructor contract |
| Internal message preparation | `0xfffffe000bcc69fc` tests bit 37; `...6ae0` calls `0xfffffe000bcc2390` | Signs descriptor pointers in internal storage |
| OOL-memory pointer signing | `...bcc2414`-`...2424`, shared PAC/store block `...23b4` | PACDA with discriminator `0x5d4f` and descriptor storage address |
| Internal copyin, type1 | `...bcc6d68`-`...6d80` | Advances over the already prepared memory descriptor; no user-VA-to-copy conversion occurs on this case |
| Return to kext | `0xfffffe000bcc7608` tests bit 37; type1/3 path `...7748`-`...7758` and `...7790` | Authenticates original descriptor pointer with AUTDA and writes unsigned pointer to the destination descriptor |
| Non-kext-policy copy/return | Other captured branches | Relocates authenticated pointers to the new descriptor storage and signs again |

For type1/3, the native address modifier is `(descriptor_address & 0x0000ffffffffffff) | (0x5d4f << 48)`, formed by replacing the high 16 bits with MOVK. Null pointers bypass the sign/auth operations. The relevant descriptor stride is 16 bytes and its type byte is at +11. The [pinned message implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_kmsg.c#L4905) corroborates the kext sign/strip distinction; the target's raw PAC instructions and branch value are independently retained.

This explains why the protected kext can use raw VM-copy pointers while the kernel's message storage authenticates them. It does not establish that observed pointers authenticate successfully at runtime, or that an arbitrary ordinary memory address is a valid VM-copy object. Port-array and guarded-descriptor cases are captured but are not assigned complete contracts by this increment.

## Reproduction, bounded findings and quality gates

```sh
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_kernel_rpc_transport.py
clang -target arm64e-apple-macos13.0 -std=c11 -fsyntax-only \
  triage_evidence/kernel_rpc_transport_layouts.c
```

Extraction uses O(B+N+F+D) time/space for original bytes B, nlist records N, function starts F and decoded instructions D, excluding solver-dependent proof complexity. Descriptor loops scale with descriptor count; RPC waiting/retries have no finite duration bound established here. Compile assertions check the 32-byte header, 16-byte descriptor, offsets and 400-byte reply storage; they do not define complete private kernel objects. [Source hashes](triage_evidence/kernel_rpc_public_sources.json) retain public-source provenance separately from the target collection.

| Impact | Additional finding / remaining boundary |
| --- | --- |
| High | The reply endpoint is thread-bound and reused; the null/no-op MIG helpers are insufficient to reconstruct its lifecycle. |
| High | Caller send-reference, message COPY_SEND, temporary object retain and reply send-once creation have distinct native accounting paths. Complete protected publication/close ownership remains unknown. |
| High | Descriptor PAC is an actual kext/internal ABI transition. Static collection chained-fixup normalization does not validate these runtime signatures. |
| Medium | The 400-byte receive cap resolves the normal reply's minimal trailer placement. It does not explain the daemon request's audit-trailer allocation. |
| Medium | Receive retries and teardown depend on thread state; no application-visible finite RPC deadline is established. |
| Medium | Downstream user-header deflation, namespace copyout, reply-port linkage/destruction and target-source provenance remain concrete continuation leads. |

QG1 factual technical scope. QG2 R1-R5 and falsification probes explicit. QG3 this increment covers deeper RPC reply endpoints, local ownership, interrupt/size contracts and kext descriptor PAC; the full original objective remains active. QG4 byte widths, bit-vector guards, units and complexity are explicit. QG5 endpoint/right/reference distinctions, source-correlated names, initialized trailers and runtime PAC boundaries remain separate. QG6 original hashes/function metadata, exact symbols, instructions and proof queries are retained independently from pinned reference source. QG7 bounded impact-labeled findings and deeper leads are listed above.

## Subsequent native user-delivery recovery (2026-11-01)

[kernel_user_copyout_report.md](kernel_user_copyout_report.md) now recovers matching normal user receive-results, namespace/header conversion, OOL mapping and packing. It partially supersedes the user-conversion gap above while preserving unknown installed CF delivery, native runtime names and downstream namespace internals. It also recovers the null-task kernel audit template and the distinction between requested/advertised and actually delivered trailer bytes. The kernel caller's 400-byte reply receive cap remains a different direction and thread context from the daemon's still-unknown request receive allocation.

## Subsequent Mach2 dispatch and shared receive implementation (2026-11-01)

[kernel_dispatch_report.md](kernel_dispatch_report.md) connects the original user-library trap selectors through complete original Mach/BSD dispatch and name tables. Mach2 handler0xfffffe000bcdd73c calls user receive helper0xfffffe000bcdd4e4, which resolves a current-space receive name through0xfffffe000bcc8cf4, stores user-receive state and calls the same common queue receive0xfffffe000bcc83b4. Its continuation reaches0xfffffe000bcdcc7c user copyout. This shared implementation preserves different caller state and result handling.

The user helper compares an authenticated thread+0x450 pointer on its selected SYNC_WAIT path; this is a distinct coordinate from the kernel RPC endpoint at thread+0x3f0 recovered here. Library task reply names are separate u32 namespace values. Full create/bind/unbind/reference/destruction accounting and actual endpoint identity remain open; a common receive callee does not establish endpoint equality.

## Subsequent namespace and reply-link reference accounting (2026-11-01)

[kernel_namespace_report.md](kernel_namespace_report.md) recovers selected creation/binding/unbinding and linkage contracts below this transport. Link0xfffffe000bccef30 acquires a destination object hold and a separate send-turnstile primary hold; selected adjust/unlink paths release both. User special-reply replacement clears/releases its old thread+0x450 binding before allocation, while kernel thread+0x3f0 unbind clears/unlinks and reaches destruction0xfffffe000bccdbb4. Actual destruction internals and complete state coverage remain open.

The same report separates namespace lookup's locked/no-extra-reference result, receive-name wrapper's retained/unlocked result and receive-results' matching decrement. These are additional scopes alongside the temporary destination retain, COPY_SEND and MAKE_SEND_ONCE documented here. Six proofs and93 private fixtures retain explicit lock/PAC/turnstile/allocator models; they do not establish native endpoint identity or a live transaction.
