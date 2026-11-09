# Kernel-to-daemon message delivery: namespaces, OOL mappings and audit trailers

The matching kernel's native user receive-results path calls normal message copyout, maps OOL memory into the receiver's map, packs descriptors, contracts the header from 32 to 24 bytes and copies the resulting message/trailer to user memory. This supplies implementation evidence for the previously identified 88-byte kernel / 80-byte daemon RPC502 ABI correspondence.

The request's audit provenance is also more specific: the kernel RPC copyin path initializes its trailer with a null task, selecting a native constant whose eight audit words are zero. The inspected deflater preserves those audit bytes, and the daemon MIG502 stub copies all 32 bytes to its application argument. Subject to the explicit transport/framework assumptions below, this is the kernel audit token, separate from the constructor's `origin` scalar and from any initiating user task's audit token.

## Provenance and assumption register

Analysis date: 2026-11-01. All static kernel addresses are unslid. Kernel collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, embedded kernel UUID `9b65bd6e-027b-34d1-a22b-ac03dccffc84`. The refreshed daemon thin image is `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.

[Native contracts and fixtures](triage_evidence/kernel_user_copyout_contracts.json) retain 10 compiler-bounded kernel ranges, 102 direct call/tail edges, 38 original instruction checks, two complete-domain bit-vector checks, two synthetic packing profiles and a synthetic trailer-delivery witness. The script verifies the collection/image hashes before extraction. Original `LC_FUNCTION_STARTS` boundaries and exact nlist matches remain separate from source-correlated helper names. No target code was executed and no IDB was modified.

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| U1: supplied images are the intended build and retain the observed layout | Native addresses, ABI correspondence and constant contents | Recheck hashes, compiler bounds, original bytes and prior collection/extracted-kext section correspondence. File identity does not attest live RAM or historical zut state. |
| U2: valid current-thread, task, IPC space, VM map and callee contracts apply | Receiver namespace/map roles and successful copyout | Trace every contributing field/callee and observe a native receive. Raw pointer/zone checks alone do not establish live object validity or policy authorization. |
| U3: the receiving map takes the 64-bit branch and descriptors have the recovered supported types | The 80-byte daemon request and 16-byte memory descriptor | Read receiver map+0x18; native 64-bit selection is `max_offset >= 0xf0000001`. The 32-bit alternative is independently represented and changes the message size. |
| U4: ordinary scalar receive, with representable message-plus-trailer arithmetic and an initialized trailer | Copy-capacity bounds, audit trailer and truncation witness | Check receive option bits, vector/aux paths, arithmetic guards and exact buffer extents. Framework allocation size is distinct from the supplied receive capacity. |
| U5: intervening native/framework operations do not replace the relevant message/trailer, and deliver the required audit prefix | Zero audit words reach the RPC502 application argument | Installed-cache CF capacity/options/forwarding are now recovered in [cf_receive_report.md](cf_receive_report.md); resolve runtime voucher hooks, attest actual modules and capture post-hook native bytes. The static compatible path is not an observed live round trip. |
| U6: pinned public XNU functions explain conventional names/types for stripped helpers | Descriptive helper roles and ownership interpretations | Match exact target source/build or independently recover all callees. Two concrete native/reference differences are documented below. |

## Native receive and namespace path

```text
daemon receive thread / received internal kmsg
    |
    v
0xfffffe000bcdcc7c  receive-results range
    | 0xfffffe000bcdcf28
    v
0xfffffe000bcc4e98  normal header/right copyout
    | tail branch 0xfffffe000bcc541c
    v
0xfffffe000bcc5564  descriptor copyout into receiver VM map
    |
    v
0xfffffe000bcdcf9c -> 0xfffffe000bcc62d0
                     header/descriptor/trailer packing and copyout
                                      |
                                      v
                        daemon request buffer / MIG502
```

These are normal user receive paths, distinct from the kernel caller thread's reply wait in [kernel_rpc_transport_report.md](kernel_rpc_transport_report.md). The receiver and kernel RPC caller are not assumed to be the same thread or task. Actual CF-to-trap delivery for the installed daemon remains unobserved.

The receive-results range loads current-thread state, a task-associated IPC space and the receiving thread's map. At `...bcdcf18`-`...cf28` it passes `(kmsg,space,map,options)` to normal copyout. Successful copyout reaches the packing call with status 0; selected body-error paths also copy the partially converted message with an error status. The [pinned receive implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/mach_msg.c#L279) corroborates those roles; it is not established as the exact target revision.

| Header role | Native conversion evidence | Result before final packing |
| --- | --- | --- |
| Internal local/reply object | Name creation/conversion paths populate SP+0x48 | Becomes outgoing user remote/reply name |
| Internal remote/destination object | `...bcc52b4` supplies SP+0x4c to `0xfffffe000bcca164` | Becomes outgoing user local/service receive name |
| Final pointer-width header slots | `...bcc53c8` loads the two u32 names; `...53dc` stores their zero-/sentinel-extended values | Namespace conversion precedes narrowing; an object pointer is not simply truncated into a port name |
| Header packing | `...bcc663c` uses XTN on the converted values | User remote/local fields are 32-bit names in the 24-byte header |

This corroborates why RPC502 application argument 0, taken from user header+0x0c, is the receiving-service name. The reply destination instead comes from request+8 and is preserved by the [daemon reply callback](daemon_receive_interface_report.md). Native downstream name creation, locking, inactive-port cases and entry-table policy are captured only at their caller boundaries here.

The adjacent range `0xfffffe000bcc5b2c` is a **pseudo-receive** path. Its sentinel/current-thread behavior and option handling differ; it is retained in the artifact and is not used as proof of ordinary daemon receive behavior.

## OOL copy-object validation and receiver mapping

For descriptor type 1 or 3, the native loop at `0xfffffe000bcc5664` authenticates its VM-copy pointer with the descriptor storage address and discriminator `0x5d4f`, then invokes validator `0xfffffe000bdd148c` at `...5698`. Descriptor extent starts as a zero-extended u32. A null copy sets the resulting user address and extent to 0.

The validator checks the copy object's address range/metadata before its type/size decisions. Its observed metadata class comparison is 0x13; malformed provenance enters a failure helper, rather than merely returning a successful descriptor. No claim of forgeability or complete object-integrity enforcement is made from this slice.

Let N be the descriptor's initial extent and C the copy object's 64-bit extent at+0x20. The native type byte is at copy+0x2d:

| Copy type | Native size rule | Result |
| --- | --- | --- |
| 3, source-correlated kernel buffer | C==N | Accepted; working extent unchanged |
| 2, source-correlated entry list | N<=C<=round_page(N,receiver_page_size) | Accepted; working extent replaced by C |
| Other / inconsistent size | Does not satisfy either branch | Validator false; descriptor path enters a panic continuation |

The receiver page shift is loaded from map+0x2c, with a null-map fallback 14. This size validator may enlarge the working extent for entry lists. The [pinned VM validator](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/vm/vm_map.c#L11702) supplies the conventional type names; native type numbers, fields and guards are retained separately. The actual runtime copy type and extent for a FairPlay filename remain unknown.

| Mapping case | Native call / behavior |
| --- | --- |
| Direct path | `...bcc56e8` -> `0xfffffe000bdcb374`, arguments `(map,&address,copy,validated_extent,1)` |
| Entry-list misalignment | Kernel alignment mask 0x3fff tests the copy offset and descriptor extent; misaligned cases allocate a rounded receiver region at `...5878`, then overwrite it at `...58b0` |
| Overwrite failure after allocation | `...58c8` deallocates the allocated base/extent before common error handling |
| Mapping failure, status 6 | Sets descriptor error bit 0x400 |
| Other mapping failure | Sets descriptor error bit 0x1000 |
| Common failed mapping cleanup | Calls exact `_vm_map_copy_discard` at `...58f8`; outputs zero address/extent |
| Accepted mapping | Replaces the authenticated copy pointer with the unsigned receiver VA and writes the resulting u32 descriptor extent at `...55b4`/`...55b8` |

The direct target is also used by exact exported `_vm_map_copyout` at `0xfffffe000bdd1574`; that wrapper obtains the copy extent from+0x20 and passes final argument 1. This ties the user OOL mapping implementation to the previously recovered kext reply-copyout implementation, while preserving their different receiving maps. Complete VM implementation semantics remain a deeper contract.

The descriptor loop ORs errors across descriptors and returns `0x1000400c | error_bits` when any accumulated error is nonzero. A body error is therefore not an all-or-nothing rollback of every earlier descriptor conversion. The receive-results range has an explicit partially converted body-delivery path; framework handling of that status remains unknown.

For RPC502, refreshed daemon instructions `0x1000050f4`-`...5100` require the received descriptor extent to equal the repeated extent at+0x34. Thus an entry-list expansion C!=N, with the repeated value unchanged, is rejected before the application call. The already recovered callback's recognized-error cleanup destroys the request after preserving its reply right. This is a conditional compatibility constraint, not evidence that real filename requests use a mismatching expanded extent.

## Packing contract and flags

For supported descriptors, the native packing loop walks backward from the descriptor array's end and writes the contracted forms backward. Relative descriptor order is preserved. The remaining inline payload is not interpreted as port/pointer fields by that loop.

| Field | Kernel internal | User64 memory descriptor | User32 memory descriptor |
| --- | --- | --- | --- |
| Header bytes | 32 | 24 | 24 |
| Memory descriptor bytes | 16 | 16 | 12 |
| Descriptor address width | 8 | 8 | 4 |
| Flags within descriptor | +8 | +8 | +8 |
| Extent within descriptor | +12 | +12 | +4 |
| Single-OOL RPC502 request total | 88 | 80 | 76 |

The native map-width predicate is `map.max_offset >= 0x00000000f0000001`; it is not inferred solely from the executable's CPU subtype. Port descriptors take 12 bytes even for a 64-bit recipient; a blanket eight-byte total contraction is valid for the recovered 64-bit OOL-memory message, not every Mach message shape.

For original flags F, the type 1/3 user flag word is:

```text
user_flags = (F & 0xff00ff00) | (((F >> 8) & 0xff) == 1 ? 1 : 0)
```

The native code masks the word, compares its copy byte to 1 and conditionally increments the masked result. The deallocate byte is rebuilt from the copy method; it is not preserved from the sender's original deallocate byte. Thus kernel request flags `0x01000100` become user request flags `0x01000101` on this path. The daemon stub checks the descriptor type and matching extents; its refreshed guard does not compare the complete flag word.

One SMT query verifies this flag identity across all 2^32 input words. Synthetic 64-/32-bit profiles check 80-/76-byte request packing, port-name placement and the ordinary 64-bit repeated-length offsets. These fixtures are explicit models of retained native operations, not native delivery tests or independent proof of all source-to-model translations.

## Kernel audit-template path

In kernel RPC copyin, `0xfffffe000bcc6d28` sets X1=0 before calling initializer `0xfffffe000bcc4194`. The null-task branch selects the constant at `0xfffffe0007010a68`: it copies 64 bytes and separately zeros the final 4 bytes. Its relevant fields are:

| Trailer offset | Size, bytes | Native constant value |
| --- | ---: | --- |
| +0 type | 4 | 0 |
| +4 initial advertised extent | 4 | 8 |
| +8 initial sequence | 4 | 0 |
| +12 security token | 8 | u32 words `(0,1)` |
| +20 audit token | 32 | Eight zero u32 words |
| +52 onward | 16 | Zero in template; later context/receiver fields may be written |

The [pinned header](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/message.h#L881) defines the conventional kernel audit token as eight zeros. Here the native template, null-task predecessor and daemon's source-image loads independently establish the bytes and path.

At receive packing, `...bcc6468` writes the requested trailer extent, updates sequence and clears/writes receiver context starting at trailer+52. It does not rewrite audit bytes +20..51. The daemon's `0x1000051cc`/`...51d0` reads 16 bytes at each of those two halves and places the 32-byte value in its application argument.

Under U2/U4/U5, the ordinary kernel RPC502 therefore supplies the kernel audit value, while the separate origin scalar remains the constructor's launch/load origin. This token does not encode the initiating user process's distinct audit identity. The subsequent [application recovery](daemon_rpc502_report.md) establishes a local audit-PID-zero predicate reached through `0x100422d48`. Complete service-name-dependent policy and authorization remain unknown; the transfer alone does not establish those properties.

## Requested versus delivered trailer extent

The native selector extracts receive option bits 24..27. Its requested trailer sizes are:

| Element selector | Requested bytes, map32 | Requested bytes, map64 |
| --- | ---: | ---: |
| 0 | 8 | 8 |
| 1 | 12 | 12 |
| 2 | 20 | 20 |
| 3, conventional audit | 52 | 52 |
| 4, conventional context | 56 | 60 |
| 7, conventional AV | 64 | 68 |
| Other recovered cases | 68 | 68 |

Pseudo-receive sentinel -2 bypasses this normal trailer generation. Vector/aux/stack branches are retained but are not substituted for the following ordinary scalar contract.

Let U be user inline bytes, T requested trailer bytes and B supplied receive capacity, with U+T representable as u32. If B<U, packing reports `0x10004008` and zeros output size fields. Otherwise the delivered byte count is `min(U+T,B)`. If the trailer is truncated, native `...bcc6670` reports the actual trailer extent `B-U` in the receive-result record, while the already written trailer's advertised size can remain T. A second SMT query bounds the delivered count and actual trailer extent under these guards.

For a synthetic U=80 bytes, T=52 bytes, B=112 bytes case:

```text
delivered message       [ 0, 80)
delivered trailer       [80,112)  =32 bytes
advertised trailer                   52 bytes
MIG502 audit reads      [100,132) =32 bytes
audit bytes not delivered       [112,132) =20 bytes
```

The stub's type 0 / advertised-size>=32 guard accepts that advertised extent. The witness demonstrates an interface prerequisite: delivered and allocated trailer extents must cover the full52-byte prefix, or equivalent framework guarantees must apply. It is not a native reachability, out-of-allocation read, crash or policy-bypass finding. An allocation may be larger than receive capacity; bytes outside the delivered prefix then still lack fresh message provenance.

The later [installed-cache CF recovery](cf_receive_report.md) narrows this prerequisite: initial capacity is3072 bytes and the requested map64 AV trailer is68 bytes. All eleven original fixed-size MIG guards accept inline sizes no greater than164 bytes, so complete trailers fit. RPC502's80-byte inline form requires148 bytes including the AV trailer and its audit prefix ends at132 bytes. The synthetic B=112-byte case above does not describe that ordinary fixed-size CF path. Actual loaded-library pairing, runtime voucher callback effects, malformed/other receive routes and native delivery remain separate unknowns; incoming OOL/right disposal is not established by CF's inline-buffer cleanup.

## Native versus reference-source differences

| Boundary | Matching native observation | Pinned reference source |
| --- | --- | --- |
| Scalar truncated-trailer result | Reports `B-U`; witness value 32 bytes | The saved `ipc_kmsg_put_to_user` expression subtracts `B-(U+T)` from T; same witness gives 72 bytes |
| Misaligned OOL overwrite failure | Explicit deallocation of newly allocated receiver region before discard | The saved OOL-descriptor helper has no corresponding explicit deallocation in that branch |

These differences are evidence that the pinned source must not replace target analysis. Exact target-source revision and the history/reason for these differences are unknown. The native script/report models the matching collection's instructions.

## Reproduction, bounded findings and quality gates

```sh
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_kernel_user_copyout.py
clang -target arm64e-apple-macos13.0 -std=c11 -fsyntax-only \
  triage_evidence/kernel_user_copyout_layouts.c
```

Extraction uses O(B+N+F+D) time/space for original bytes B, symbol records N, compiler starts F and decoded instructions D; SMT complexity is solver-dependent. Descriptor conversion/packing scales with descriptor count plus nested-array work; VM mapping and namespace operations are separate callees whose full cost is not derived here. Compile assertions cover partial user descriptor/request/audit layouts, not complete private structures. Public-source hashes are retained in the prior [message-source manifest](triage_evidence/kernel_rpc_public_sources.json), [VM/receive-source manifest](triage_evidence/kext_port_vm_public_sources.json) and [header-source manifest](triage_evidence/daemon_receive_public_sources.json).

| Impact | Additional finding / remaining interface |
| --- | --- |
| High | The kernel RPC request's native audit template carries eight zero words; initiating-user provenance does not follow from the constructor's origin scalar. Application use of this token is a direct next lead. |
| High | Native receiver namespace conversion and VM-copy mapping bridge the static kernel/user ABI; actual installed-framework delivery and runtime object identities remain unobserved. |
| High | Requested, advertised, delivered and allocated trailer extents are distinct; the synthetic 20-byte delivery gap makes CF receive guarantees a concrete proof obligation. |
| Medium | VM-copy extent expansion can conflict with strict generated repeated-length validation; actual copy type/extent remains unknown. |
| Medium | Received descriptor deallocate flags are reconstructed from copy semantics, so sender/receiver flag-byte equality is not an ownership invariant. |
| Medium | Two matching-native/reference differences constrain source-derived models. |

QG1 factual technical scope. QG2 U1-U6 and falsification probes explicit. QG3 this increment covers native user receive, namespace/header roles, OOL mapping/extent, audit provenance and trailer contracts; the full original objective remains active. QG4 byte widths, offsets, guarded arithmetic, layouts and complexity are explicit. QG5 normal/pseudo receive, caller/receiver threads, requested/delivered/allocated extents and source differences are separated. QG6 original bytes, compiler bounds, symbols, refreshed daemon guards, synthetic witnesses and source context remain distinct. QG7 bounded impact-labeled findings and remaining interfaces are listed above.

## Upstream original Mach2 receive contract (2026-11-01)

[kernel_dispatch_report.md](kernel_dispatch_report.md) now supplies an upstream static path: original Mach table[-47] ->0xfffffe000bcdd73c -> user receive helper0xfffffe000bcdd4e4 -> common queue receive0xfffffe000bcc83b4 -> tail branch0xfffffe000bcdd708 to the receive-results range0xfffffe000bcdcc7c analyzed here. Packed receive names, scalar/vector capacities, timeout narrowing, effective policy and selected thread-state publication are recovered at their actual native loads/stores.

Receive auxiliary validation can follow an already attempted send, while primary receive-buffer consequences remain in receive/copyout. This preserves the distinction between preflight failure, queue consumption, partial body conversion and delivered/truncated bytes. The new original table/reference differences are additional to the packing/VM differences documented here; effective runtime policy and installed CF reception remain unverified.

## Upstream namespace retain and pre-copyout release (2026-11-01)

[kernel_namespace_report.md](kernel_namespace_report.md) now recovers receive-name lookup through encoded namespace entries and post-lock identity/generation/rights checks. The receive wrapper adds an object reference before unlocking and publishes it to the user receive helper. Receive-results loads it from thread+0x398, performs selected special-reply completion and decrements object+4 at0xfffffe000bcdce04 before later message/header/OOL copyout. Message-owned rights remain distinct from that receive-object reference. Private acquisition/release phases balance the selected counters; complete queue/continuation and installed-framework behavior remain unverified.
