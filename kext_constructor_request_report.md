# Original constructor entry to RPC502/RPC700 request boundary

The original `_fcHfFIGhsx` entry at `0xfffffe000a66a7e0` now runs continuously to the common kernel MIG transport boundary in 25 private CPU cases. This closes the earlier predecessor gap for the ordinary filename request, derives the previously conditional W20=0xC96 allocation control, and establishes both staging allocation and remainder-fill formulas. There are 21 RPC502/host-slot17 prefixes and four RPC700/host-slot34 prefixes. No request is sent and no constructor result or registry publication is established.

The evidence consists of [original ranges, exact symbols, metadata and proofs](triage_evidence/kext_constructor_request_source.json), [complete private source journals](triage_evidence/kext_constructor_request_profiles.json), [independent CPU and contract checks](triage_evidence/kext_constructor_request_checks.json), [preservation audit](triage_evidence/kext_constructor_request_delivery.json) and [scoped quality gates](triage_evidence/kext_constructor_request_quality_gates.json). Earlier [port/VM contracts](kext_port_vm_report.md), [typed security-record contracts](kext_security_record_report.md), [page lookup](kext_page_context_report.md) and [retirement](kext_context_retirement_report.md) retain their original evidence boundaries. This report supersedes only their allocation/fill and constructor-predecessor unknowns within the scope stated here.

Analysis date: 2026-11-04. Static addresses are unslid. Original collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Normalized kext SHA-256: `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Source instructions are read from the original collection and matching normalized kext; authenticated pointer values are explicitly decoded logical fixtures. IDA was unnecessary for this increment and was not changed. Prior local memory supplied only evidence-boundary methodology, not target facts.

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CR1 | The pinned collection and supplied kext are the intended build; all addresses and symbol assignments depend on this. | Rehash originals; compare captured instructions and original pointer metadata. Native pairing with the daemon remains unknown. |
| CR2 | Explicit initialized flag `0xfffffe000ccca078=1`, logical original image state, and zero-backed private RAM describe a conditional initialized execution. | Recover native initialization and mutable-global epochs; vary startup state separately. No native initialization claim follows from these fixtures. |
| CR3 | Allocator register returns designate separate, zero-backed private regions of the declared sizes; staged and filename regions do not alias. | Check all modeled returns, metadata sizes, complete CPU writes and region canaries; inspect native allocator initialization before extending this to native objects. |
| CR4 | Filename fixtures are readable, NUL-terminated, and have the supplied length. | Reconstruct every filename byte independently; use lengths 0,1,28,4095,4096,4097,16383,16384. Large/wrapped native lengths remain untested. |
| CR5 | Host self, host-special-port, allocation, memcpy and copyin results have the explicitly modeled ABI effects. | Validate every model argument, memory effect, preserved register and result in a fresh CPU map; inspect original callees for native behavior. No host lookup, right acquisition or VM operation executes here. |
| CR6 | PAC instructions and authenticated transfers may be represented by declared logical edges. | Verify each original instruction, destination and modifier against recorded register state; native authentication validity remains unknown. |
| CR7 | Local arithmetic seeds/encoded inputs apply to the two symbolic components. | Independent entry-to-boundary replay checks these seeds in every retained case. SMT proves the local identities over their full stated word domains, not all constructor paths. |
| CR8 | Observed prefixes stop before common transport; post-transport behavior is unknown. | Continue original transport/receive/reply/parser/publication code with separately justified contracts; require actual peer/build/credential identity for a native interaction claim. |

The dependent findings below are conditional on CR1-CR8 as applicable. Exact source byte identity, mathematical word identities and finite CPU-path results are separate evidence classes.

| Entry register | Preserved constructor argument | Original store |
| --- | --- | --- |
| X0 | Filename pointer, u64 | `...a810` spill, `...aa88` record+0 |
| X1 | Raw CPU-type value, u64 | `...a80c` spill, `...aa90` record+0x10 |
| X2 | Raw CPU-subtype value, u64 | `...a80c` spill, `...aa90` record+0x18 |
| low32(X3) | Origin, u32 | `...a808` spill, `...aa98` record+0x20 |
| low32(X4) | Mode, u32 | `...a808` spill, `...aa98` record+0x24 |
| X5 | Output-handle pointer, u64 | `...a804`, preserved output pointer |

The dispatcher argument record begins at wrapper SP+0x40 after copying the entry spills; its+8 output word is a later result location. CPU-type/subtype fields retain high bits in the source ABI: they must not be reduced to u32 merely because ordinary provider values fit 32 bits. Origin and mode are truncated at the wrapper stores. The high-bit fixtures preserve these distinctions. No returned-handle value is produced before the stop.

The source wrapper requests a 16384-byte frame aligned to 64 bytes at `0xfffffe000a66a988`, then `site.AllocType` size4096 at `...aa1c`, prepares its arena at `...aa7c`, and invokes the generic dispatcher at `...ab50`. The operation tag is 0xD11612F2. Original dispatcher source requests a separate 172-byte buffer at `0xfffffe000a60aa40` and `site.FPAppSecurityInfo` size152 at `...ab2c`. These are distinct allocations. The latter's source W20=0xC96 is now derived from original entry under CR2-CR6 rather than injected at a mid-function entry.

| Mode condition | Host lookup identifier | RPC client | Constructor call site | Client transport call site |
| --- | --- | --- | --- | --- |
| low32(mode)==1 | 17 | RPC502, `0xfffffe000a5a2064` | `0xfffffe000a60b8a8` | `0xfffffe000a5a20f8` |
| low32(mode)!=1 | 34 | RPC700, `0xfffffe000a5a22d4` | `0xfffffe000a60d3bc` | `0xfffffe000a5a2368` |

The host call is `_host_get_special_port(host_priv_self(), -1, identifier, &C[0x18])` at `0xfffffe000a60acb8`. Comparison/CSEL at `...ac10`/`...ac14` selects the identifier; the RPC branch independently compares record+0x24 against1 at `...b7f0`. Retained mode inputs are 1,0,2,0xFFFFFFFF,0x100000001 and0x100000000. The last two select17/502 and34/700 respectively. This establishes conditional source routing; actual endpoint identity, slot34 registration and acquired send-reference balance remain unknown in this increment. The model uses one opaque kernel port object in separate runs and does not establish equality of the real slot17 and slot34 endpoints.

Let N be the strlen result, n=low32(N), M=zero_extend64((n+1) mod 2^32), p=low5(*PAGE_SHIFT), and Q=2^p bytes. The earlier filename-extent proof establishes M. Two new source-derived SMT checks establish:

```
A = (M + Q - 1) & ~(Q - 1)       staging allocation extent, bytes
Z = A - M                       zero-fill extent, bytes
```

The allocation identity covers every u32 M and u32 page-shift word under the recorded local seeds. The fill identity covers every u64 A/M pair as modular arithmetic under its encoded-input premises. For the allocation contract, A>=M and no u64 addition overflow occurs because M<=2^32-1 and Q<=2^31. This is a representation result; readable source bytes and successful native allocation still require CR3-CR5. M can be zero after the earlier u32 length wrap. Such a native filename is not exercised here.

| Source operation | Site | Established call/data contract |
| --- | --- | --- |
| Staging allocation | `0xfffffe000a60b518` | `kernel_kmem_alloc(*ipc_kernel_map, &C[0x80], A)` |
| Filename copy | `0xfffffe000a60b608` | Exact `_memcpy`/`_memmove` alias target; copies M bytes to staging |
| Remainder fill | `0xfffffe000a60b71c` | Original local helper `0xfffffe000a687d64(staging+M,0,Z)`; executes source stores |
| VM copy creation | `0xfffffe000a60b780` | `kernel_vm_map_copyin(*ipc_kernel_map,staging,M,0,&C[0x28])` |
| RPC destination | `...b7f8` | Loads the opaque kernel port object from C+0x18 |
| RPC OOL argument | `...b7fc` | Loads the opaque vm_map_copy_t from C+0x28 |

For N=28 and p=14: M=29 B, Q=16384 B, A=16384 B and Z=16355 B. For N=4095,p=12: M=A=4096 B and Z=0 B. For N=4096,p=12: M=4097 B,A=8192 B,Z=4095 B. The copied terminating NUL belongs to M. Source fill covers exactly [staging+M,staging+A); the byte at staging+A retains0xA5. Tested page shifts are12,14,16; the formula's symbolic shift domain is broader than these environmental fixtures.

```
filename VA -- memcpy M --> staging VA in private ipc_kernel_map model
                               |
                       source clears A-M bytes
                               |
                      copyin model yields COPY
                               |
mode32 --> host slot17/34 --> PORT --> RPC502/700 pre-transport buffer
                                                 |
                             stop before mach_msg_rpc_from_kernel_proper
```

PORT, COPY and staging are separate representations. PORT is a kernel ipc_port object value, not a daemon-local u32 Mach name. COPY is an opaque vm_map_copy_t result, not the filename VA. Actual port namespace conversion and VM-copy effects are not exercised.

Both clients execute the matching kernel `_mig_get_reply_port` body at `0xfffffe000bcf5f18`, which returns NULL in this collection. They then stop at exact `_mach_msg_rpc_from_kernel_proper`, `0xfffffe000bcf5e28`, with X0=request-buffer address, X1=88 and X2=400. Thus no receive-right allocation or daemon reply name is established by this prefix.

| Kernel request offset | Width, bytes | Value at the pre-transport stop |
| --- | --- | --- |
| 0x00 | 4 | Header bits0x80001513 |
| 0x04 | 4 | 0 in the private fixture; size is not yet supplied by the unexecuted transport |
| 0x08 | 8 | PORT, acquired opaque kernel object |
| 0x10 | 8 | NULL from original mig_get_reply_port |
| 0x18 | 4 | 0 in this fixture |
| 0x1C | 4 | ID502 or700 |
| 0x20 | 4 | Descriptor count1 |
| 0x24 | 8 | COPY, opaque copy object |
| 0x2C | 4 | Descriptor control word0x01000100 |
| 0x30 | 4 | M, descriptor byte count |
| 0x34 | 8 | NDR bytes `0000000001000000` |
| 0x3C | 4 | M, separate argument byte count |
| 0x40 | 8 | Raw CPU type, preserving X1's64 bits |
| 0x48 | 8 | Raw CPU subtype, preserving X2's64 bits |
| 0x50 | 8 | Zero-extended low32(origin) |

This is the kernel's 88-byte construction buffer, not an observed userland wire packet. Its header, pointer fields and zero size must retain that representation boundary. Both RPCs pass fixed-record destinations in X6/X7: the152-byte FPAppSecurityInfo owner and separate172-byte output buffer. Later successful reply copy, mapping installation and registry publication are outside these prefixes.

Verification covers nine explicit source ranges/1986 instructions, two metadata views, two unsatisfiable mismatch proofs, 25 continuous original prefixes/96101 instruction visits, and fresh replay of every recorded CPU read/write, logical authenticated edge, model memory effect and final boundary. Replay checks44168 source writes/350351 B,8025 reads/44700 B,850 logical indirect edges,250 declared API models,100 model memory effects/91045 B and146 constructor snapshots. The byte oracle checks90445 filename bytes and323251 zero-filled bytes. All25 output-handle canaries remain unchanged. Twenty-one prefixes select502/17 and four select700/34. Eight cases use p=12,16 use p=14,one uses p=16. These are finite cases, not exhaustive path coverage. Both symbolic arithmetic domains are independently checked with Z3.

Reproduction uses the pinned zut virtual environment and existing Z3 runtime documented in the scripts. Run recovery, probe and validator in that order; then seal, publish the owned manifest, and run the independent full-publication audit. Each script documents its time/space bound. Recovery and checking are linear in retained image bytes/instruction or effect count apart from the timeout-bounded SMT queries; private CPU working state is bounded by one1 MiB map plus journals and original image metadata.

| Impact | Further interface to establish | Falsification / useful evidence |
| --- | --- | --- |
| High | Constructor reply-to-KBCrypt publication and output-token transform | Continue from the two original client return sites; trace owner/child/shared allocation epochs and stores through list insertion and result adapter. The page/close lookup codec does not by itself identify the constructor's returned token. |
| High | Slot17/34 endpoint identity and native pairing | Correlate actual daemon registration/build/credentials with matching-kernel host-special-port state and message conversion. The supplied RAX trace still ends with an unsuccessful UserClient open and cannot attest this constructor exchange. |
| High | Complete request/response ownership | Join common transport, translated daemon receive, application outputs, kernel reply parser and mapping cleanup. Verify object/reference ownership at each representation transition. |
| Medium | Initialization and environment dependence | Recover the real warm flag, map/page-shift publishers and serialized access. Arithmetic accepts low5 page-shift bits; that does not establish valid native page configuration for every word. |
| Medium | Sentinel and failure paths | Examine CPU sentinel branches and failed allocations/host lookup/copyin before extending ordinary-path coverage. No such branch is declared covered here. |
| Low | Meaning of opaque internal helper names | Assign roles from source dataflow/callees and byte contracts; retain unknown semantic names until those consumers are resolved. |

QG1: No normative content is required. QG2: CR1-CR8 register assumptions, dependencies and falsification probes. QG3: The increment covers constructor ABI, allocation/staging, mode/port/RPC selection, original request packing and remaining interfaces; the full goal remains active. QG4: Integer widths, modular domains and byte units are explicit; independent byte and CPU oracles reproduce all counts. QG5: Kernel pointers versus user names, allocation versus copied extents, pre-transport size, logical PAC and native effects remain distinct; failure/sentinel/publication frontiers are unresolved scope, not positive claims. QG6: Original bytes, exact collection symbols, type-view fixups, recorded instruction journals and two source-derived proofs provide primary provenance. QG7: Bounded further work is impact-labelled above. All gates pass for this increment; native IPC, VM effects, authentication, peer identity, reference balance and full lifecycle remain unknown.
