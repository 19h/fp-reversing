# Kext RPC destination, filename payload, VM-copy objects, and cleanup

This increment establishes three additional boundaries: the request is prepared in `ipc_kernel_map`; its kernel OOL argument is a `vm_map_copy_t`; and reply data is copyout into `kernel_map` before a page-wiring attempt. It also resolves an exact `_ipc_port_release_send` call at `0xfffffe000a615f2c`, outside the nominal dispatcher function bounds, on a locally proven post-RPC rejection route.

The two external values previously lacking exact symbols are four-byte-biased references to `_kernel_map` and `_ipc_kernel_map`. Their native adjustments are now recovered. The original count remains 415 direct exact-symbol values; adding these two explicit bias bindings gives symbolic provenance for all 417 candidate external values. This does not recover every call's semantics or establish a live native transaction.

## Provenance and assumption register

Analysis date: 2026-11-01. Kext SHA-256 is `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Matching kernel collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Addresses are unslid static virtual addresses.

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| V1: original files and live IDB describe the intended build | Native address and symbol associations | Recheck hashes, UUIDs and stored raw ranges. Five fresh live ranges match original bytes; prior whole-section collection matching remains separately available. |
| V2: the declared inherited frame, table and callee-preservation protocol apply | Path constants, scratch-pointer identities and local port-release route | Trace every predecessor, register write, indirect target and callee side effect. Do not call continuation fragments as standalone functions. |
| V3: scratch, staging, fixed-record and mapped objects do not overlap through unmodeled aliases | Same acquired port value reaches the local RPC/release loads; filename/mapped-data interpretations | Establish allocation extents and all stores/alias-producing calls. Native field equality is not complete send-reference accounting. |
| V4: input name is readable and NUL-terminated, with length fitting the stated filename interpretation; staging capacity is adequate | NUL-terminated filename payload | Check every provider caller, complete allocation-size arithmetic and length/capacity bounds. The proven extent formula also covers wrapped/truncated lengths without assuming they are valid strings. |
| V5: conventional VM API semantics match the pinned public reference | Copy-object ownership, copyout consumption and wiring interpretation | Match exact target source/build or inspect the complete matching kernel implementations. Native call targets, raw flags and argument widths remain authoritative. |
| V6: runtime map cells/page-shift values and reply objects satisfy their declared contracts | Valid mappings, alignment spans, successful application behavior | Read current values and observe a native transaction. Original pointer-cell locations and initial file bytes do not attest runtime values or reference balance. |

[Original native ranges, symbols and proofs](triage_evidence/kext_port_vm_contracts.json), [fresh live bytes](triage_evidence/kext_port_vm_live.json), and [original collection pointer provenance](triage_evidence/kernel_collection_interfaces.json) support the analysis. Automatic IDA model diagnostics and tool-dialog notifications were excluded from the evidence snapshot. The canonical per-instruction decode uses original bytes through Capstone; IDA's synthetic multi-instruction rendering is not an additional instruction proof.

## Object and namespace separation

Let F be the generic dispatcher frame, A its argument-record pointer at F+`0x28`, C its typed scratch-arena pointer at F+`0x30`, and P the separately allocated object referenced by C+`0x58`. The dispatcher reads C at `0xfffffe000a60684c` and saves it at SP+`0x1a8` at `...69dc`. It saves A separately at FP-`0xe0`. These are distinct objects from the UserClient state at UserClient+`0xe8`.

| Scratch C offset | Native role on this request path |
| --- | --- |
| `0x18` | Acquired destination `ipc_port_t` value; kernel object pointer, not a daemon-local port name |
| `0x28` | Request `vm_map_copy_t` produced by copyin |
| `0x40` | Reply OOL1 copy object |
| `0x58` | P, the destination for fixed reply record0 |
| `0x80` | Request staging virtual address in `ipc_kernel_map` |
| `0x90` | Reply OOL0 copy object |
| `0x98` | Destination pointer for fixed reply record1 |

P receives the 136-byte fixed reply record0 through RPC argument X6; fixed record1 is 172 bytes. After a normal reply mapping is accepted, native code replaces P+`0x48` with a kernel virtual address, P+`0x50` with its u32 extent, clears the qword at+`0x58`, and clears the u32 at+`0x60`. These are observed writes, not a recovered complete private type or allocation-capacity proof.

## The two map globals and named adapters

| Stored biased value | Native adjustment / site | Exact resulting symbol |
| --- | --- | --- |
| `0xfffffe0007f860ac`, pool slot `0xfffffe0008472a10` | SUB 4 at `0xfffffe000a606aa4` | `_kernel_map`, pointer cell `0xfffffe0007f860a8` |
| `0xfffffe0007efa634`, pool slot `0xfffffe0008472350` | Pre-index LDR with -4 at `0xfffffe000a60b4b4` | `_ipc_kernel_map`, pointer cell `0xfffffe0007efa630` |

Both base names are exact nlist matches in the original kernel collection. Original raw chain words still encode the **biased** addresses; the native subtraction establishes the base. No nearest-symbol substitution is used. The actual `vm_map_t` values are loaded from these cells and remain unobserved runtime data.

| Adapter | Native tail stub | Exact matching-collection implementation |
| --- | --- | --- |
| `kernel_kmem_alloc`, `0xfffffe000a508e04` | `0xfffffe000a69f2f4` | `_kmem_alloc` / `_kmem_alloc_external`, `0xfffffe000bdc1b6c` |
| `kernel_vm_map_wire`, `0xfffffe000a508e0c` | `0xfffffe000a69f494` | `_vm_map_wire` / `_vm_map_wire_external`, `0xfffffe000bdcfd6c` |
| `kernel_vm_map_copy_discard`, `0xfffffe000a508e24` | `0xfffffe000a69f454` | `_vm_map_copy_discard`, `0xfffffe000bdc6308` |
| `kernel_vm_map_copyin`, `0xfffffe000a508e2c` | `0xfffffe000a69f464` | `_vm_map_copyin`, `0xfffffe000bdd1594` |
| `kernel_vm_map_copyout`, `0xfffffe000a508e34` | `0xfffffe000a69f474` | `_vm_map_copyout`, `0xfffffe000bdd1574` |
| `kernel_kmem_free`, `0xfffffe000a508e4c` | `0xfffffe000a69f304` | `_kmem_free` / `_kmem_free_external`, `0xfffffe000bdc2f24` |

All six adapter tail branches and their original authenticated pointer slots are retained in the proof artifact, with exact symbols and original collection fixup metadata. The C export's apparent no-argument `kernel_kmem_alloc`/`kernel_kmem_free` forms are not authoritative ABI declarations.

## Filename and request-copy contract

The input name address is A+0. Call `0xfffffe000a60aecc` resolves to `_strlen`. Let N be that size_t result, n=`low32(N)`, and M=`zero_extend64((n+1) mod 2^32)`. Native mixed-width arithmetic, including its carry-select, gives **exactly M** for both the copy extent and the later VM-copyin extent; the RPC's u32 input count is the same wrapped n+1.

| Step | Native site | Established arguments / result |
| --- | --- | --- |
| Load IPC map | `0xfffffe000a60b4b4` | X0=`*ipc_kernel_map`; X21 becomes the cell address after -4 adjustment |
| Allocate staging | `...b518` | `kernel_kmem_alloc(*ipc_kernel_map,&C[0x80],allocation_extent)`; full allocation-extent formula remains unrecovered |
| Copy name bytes | `...b608` | Exact `_memcpy`/`_memmove` alias target; X0=C+`0x80` value, X1=name, X2=M |
| Fill after copied prefix | `...b71c` | Local byte-fill helper `0xfffffe000a687d64`, value 0, starts at staging+M; the full fill extent remains unrecovered |
| Form kernel copy object | `...b780` | `kernel_vm_map_copyin(*ipc_kernel_map,staging,M,0,&C[0x28])` |
| Check copyin status | `...b788`-`...b7c4` | Predicate proven equivalent to status==0 over all 32-bit statuses |
| Submit OOL object | `...b7fc` and RPC client | X1 receives C+`0x28` value; the client stores this in its kernel OOL descriptor's address field |

When N<=`0xfffffffe`, this copied M-byte prefix is the name including its terminating NUL, under V4. For n=`0xffffffff`, M is 0. For larger size_t lengths, only the low 32 bits participate. These are representation facts, not evidence that such lengths reach a valid native request or that staging capacity is sufficient for them.

This resolves the earlier unknown payload serialization on this ordinary filename-constructor path: it supplies a filename C string, with CPU type, CPU subtype and origin supplied as the three separate scalar arguments. It is not a claim about every private caller or the reserved sentinel paths.

```text
name bytes
   | memcpy M bytes
   v
staging VA in ipc_kernel_map
   | vm_map_copyin(..., destroy_source=0)
   v
request vm_map_copy_t -> kernel RPC502/700
                            |
                  userland OOL address in daemon
                            |
                  reply OOL0 / OOL1
                            |
           kernel receives two vm_map_copy_t objects
              |                         |
       copyout into kernel_map     discard on inspected branch
              |
       mapped VA + u32 extent -> P
              |
       page-wire attempt, access=3, user_wire=0
```

The kernel descriptor's copy-object pointer, daemon user virtual address, and resulting mapped kernel address are different representations. The earlier wire-offset tables remain valid; their kernel `address` fields must not automatically be interpreted as ordinary dereferenceable user/kernel payload addresses.

## Reply processing and VM ownership

For RPC status 0, the normal CPU branch (`A+0x10 != 0xabcd`) checks P's first u32 against `0xbeefed02` at `0xfffffe000a60d554`. This is an observed fixed-record marker check. The earlier constructor entry separately tests `0xabce`; these sentinels select other internal paths and are not public CPU enumerations.

| Reply action | Native site | Data flow / guard |
| --- | --- | --- |
| Copyout OOL0 | `0xfffffe000a60d61c` | `kernel_vm_map_copyout(*kernel_map,&FP[-0x80],C[0x90])` |
| On copyout error | `0xfffffe000a611790` | Discards C+`0x90` through `kernel_vm_map_copy_discard`; then optionally discards nonnull C+`0x40` |
| After successful copyout | `0xfffffe000a60d65c`-`...d680` | Checks mapped-address output against 0 |
| Auxiliary copy discard | `0xfffffe000a6123cc` | Discards nonnull C+`0x40` on the inspected successful-normal path |
| Install mapped data | `0xfffffe000a61240c`-`...2418` | P+`0x48`=mapped VA; P+`0x50`=u32 reply OOL0 extent |
| Attempt page wiring | `0xfffffe000a6124c0` | `kernel_vm_map_wire(*kernel_map,start,end,3,0)`; its return is not tested before continuing |

With runtime page shift p and mask=`u64(-1)<<p`, the observed wiring interval is:

```text
start = address & mask
end   = (address + extent + ~mask) & mask
```

This is the page-rounded covering interval when the arithmetic does not wrap and p is valid. p is loaded from exact `_PAGE_SHIFT_CONST`; no fixed page size is assumed here. Access 3 conventionally means read/write; user_wire is false. A wiring attempt is established, not its success or actual resident-page state.

The pinned [VM implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/vm/vm_map.c#L12135) specifies that successful copyout consumes the copy object and failure leaves responsibility with the caller. The native discard-on-error sequence agrees with that separately versioned contract. C+`0x90` is not explicitly cleared in the inspected success slice, so its later contents must not be treated as proof of a still-live copy object. Lifetime of the mapped region held in P and complete close/unwire/free behavior remain unresolved.

## Destination release: a verified local route

The dispatcher initializes C+`0x18` to0, passes `&C[0x18]` to `host_get_special_port`, and later loads that field into the RPC destination argument. C is rooted at the preserved SP+`0x1a8` slot. Under V2/V3, the following post-RPC route retains X28=C across ABI-conforming calls:

```text
RPC status==0
  -> 0xfffffe000a60d420
CPU field !=0xabcd
  -> 0xfffffe000a60d51c
fixed record0 word0 !=0xbeefed02
  -> 0xfffffe000a615e44
free request staging via ipc_kernel_map
  -> load C+0x18 -> ipc_port_release_send at 0xfffffe000a615f2c
```

The release selection is exhaustive over its byte index:

```text
left=0xfffffe0007941f60, right=0xfffffe000794a0d0, key=0x6d
x xor right[left[x] xor key] = 0x13  for every x in [0,255]
index=0xefe+0x13=0xf11
slot 0xfffffe000847a7a8 -> _ipc_port_release_send 0xfffffe000bcd0448
```

The preceding `0xfffffe000a615ed4` call is `kernel_kmem_free(*ipc_kernel_map,C[0x80],saved_allocation_extent)`. Its map cell was saved at SP+`0x70` at `...b720`; its extent was saved at SP+`0x78` at `...b560`. This cleanup also has incoming paths from copyout failure/null mapping and some RPC-error continuations. The full partition of those paths, normal context publication, retry/close behavior and total reference balance are not yet proven.

The field is not cleared by the inspected release call. Same pointer bits do not prove another owned send reference remains. The older candidate at `0xfffffe000a60ced8` retains an unresolved bank/object context; this report does not promote it to a confirmed release or merge it with the new site.

## Reply port supplied by the deeper kernel transport

The matching kernel's exact `_mig_get_reply_port` at `0xfffffe000bcf5f18` consists of BTI, `MOV X0,0`, RET. Thus the kernel MIG stub's local-port field starts as NULL. This is not proof that the RPC lacks a reply endpoint.

The matching `_mach_msg_rpc_from_kernel_proper` at `0xfffffe000bcf5e28` sets W3=1, X4=`0x2000000000`, X5=0 and tail-branches to common helper `0xfffffe000bcf59e0`. The separately pinned [kernel MIG source](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/ipc_mig.c#L573) identifies this as the kext-policy RPC wrapper and describes a per-thread kernel reply port in the common transport. Native getter/wrapper bytes are captured; the common helper's complete matching native receive-port creation/ownership path and the actual runtime reply object remain outstanding.

The subsequent [matching transport investigation](kernel_rpc_transport_report.md) now recovers the common helper, thread+`0x3f0` reply endpoint, creation/binding and teardown helpers, local receive/retry/size guards and distinct destination/right/reference accounting. It also establishes descriptor-pointer signing on kext entry and stripping on return, plus the clients' 400-byte receive capacity. Full downstream port destruction, user namespace conversion, protected caller lifetime and actual runtime endpoint identity remain unknown; the preceding outstanding native-helper gap is partially superseded.

## Reproduction, bounded findings, and quality gates

```sh
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_kext_port_vm.py
clang -target arm64e-apple-macos13.0 -std=c11 -fsyntax-only \
  triage_evidence/kext_port_vm_layout_contracts.c
```

Results: 11 original native ranges, five fresh live/original comparisons, 13 exhaustive selector-bank checks, six adapter bindings with original chain provenance, two exact biased-global bindings and three full-domain SMT checks (`unsat`). Compile-time assertions verify partial scratch/record offsets; they do not assert complete private object sizes. [Pinned reference-source hashes](triage_evidence/kext_port_vm_public_sources.json) distinguish public context from target evidence. Extraction uses O(B+N+D) time/space for bytes B, symbol records N and instructions D; memcpy/fill costs depend on their extents, and VM/RPC operation costs are not inferred from these local slices.

| Impact | Additional finding / remaining boundary |
| --- | --- |
| High | Request staging in `ipc_kernel_map` and reply mapping in `kernel_map` are distinct architectural interfaces, now linked to exact original global symbols. |
| High | Kernel OOL values are VM-copy objects on this path; interpreting them as ordinary addresses obscures both validation and ownership. |
| High | A concrete send-reference release site and conditional path are verified; complete acquisition-to-close reference accounting remains open. |
| High | The ordinary request's filename-plus-NUL extent is proven, including its 32-bit truncation/wrap rule. Total allocation capacity and oversized-name reachability remain unknown. |
| Medium | Reply pages are passed to a kernel wiring operation whose status is ignored at the inspected continuation. |
| Medium | The public-looking MIG reply-port getter is a native null stub; reply-port management occurs below the client stub. |
| Medium | CPU sentinel branches and reply format markers constrain where the ordinary filename/record interpretation applies. |

QG1 factual technical analysis. QG2 V1-V6 and probes explicit. QG3 this increment covers map globals, request string/copy representation, reply map/discard/wiring, a local destination release and lower reply-port delegation; the original broad objective remains active. QG4 widths, modulo arithmetic, byte fields, parameterized page spans and complexity are explicit. QG5 maps, objects, addresses, pointer bits versus references, attempted versus successful wiring and source-version boundaries are distinguished. QG6 original/live bytes, exact symbols/fixups, exhaustive bank checks, SMT results and pinned reference source are separated. QG7 impact-labeled findings and remaining interfaces are listed above.
