# VM cleanup: daemon ownership, cache transport and kernel range ABI

The daemon's `vm_deallocate` continuation reaches `_free` for its 32-byte
object, then the previously identified output-clearing boundary. In the
available cache, `vm_deallocate` aliases `mach_vm_deallocate`: trap -12 is
attempted first; only return 0x10000003 selects a Mach request fallback.
That fallback constructs message ID 4801, with a 48-byte inline request,
task/reply port names, and full-width address/size fields. The available
kernel collection's trap -12 entry resolves to the corresponding named
handler and a lower range interface using aligned start/end addresses.

The daemon-to-cache join is established at the symbol/interface level.
The cache's identity does not attest that this daemon used it natively.
No native VM/free operation, callback, kernel entry or Mach IPC was executed.
Native rights, owner extents, the message receive-side join, final admission
and publication remain unknown. The broad investigation remains active.

## Primary evidence and reproduction

| Source | Pinned identity |
| --- | --- |
| `/Users/___/Downloads/zut/fairplayd.arm64e` | SHA-256 4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e |
| Available arm64e cache | UUID 2bd06591-e751-3e84-963f-b08dab6af23a |
| Cache libsystem_kernel | UUID f2bceb9a-0fec-3c92-b6ea-8e37157050a8 |
| Original kernel collection | SHA-256 d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe |

Addresses are unslid VAs. Offsets and constants are hexadecimal unless a
decimal count is identified. Byte counts are decimal. Source file offsets,
cache subfile identities, original nlist/export records, re-export commands,
kernel chained-fixup metadata and exact instruction bytes are retained in
the [contracts ledger](triage_evidence/daemon_vm_cleanup_contracts.json).
libSystem's available load commands re-export libsystem_kernel. Target
runtime version equality is not established.

This extends the [allocation/borrowed-span report](daemon_client_object_report.md),
[cache trap interfaces](user_trap_interface_report.md), and
[kernel dispatcher](kernel_dispatch_report.md). The source files suffice;
no new IDA query, IDB change or saved-analysis-memory change was performed.

Artifacts: [48 VM-return models](triage_evidence/daemon_vm_cleanup_profiles.json),
[48 free-return models](triage_evidence/daemon_vm_cleanup_retire_profiles.json),
[30 cache profiles](triage_evidence/daemon_vm_cleanup_cache_profiles.json),
[2,048 kernel arithmetic cases](triage_evidence/daemon_vm_cleanup_kernel_components.json),
[11 original/simplified proof pairs](triage_evidence/daemon_vm_cleanup_proofs.json),
and [independent read/write replay](triage_evidence/daemon_vm_cleanup_checks.json).
All API/trap/helper outcomes and task/reply names are explicit private models,
not observations from the RAX trace or a native FairPlay execution.

From `/Users/___/dev/dylex/extracted`, apply the following prefix to the
scripts in order:

```text
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
 Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
 /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/<script>

probe_daemon_vm_cleanup.py
probe_daemon_vm_retire.py
probe_vm_cache_transport.py
probe_vm_kernel_ranges.py
recover_daemon_vm_cleanup.py
prove_daemon_vm_cleanup.py
validate_daemon_vm_cleanup.py
```

## Daemon return channel and ownership

The original call at 0x1004776C0 uses authenticated import slot
0x1010A00F8, IA diversity 3893, address diversity zero. Its modeled first
object supplies VM address=0 and size=0. Three raw return models, 0, 5 and
FFFFFFFF, all reach `_free` at 0x100541BEC with X0 equal to the first
32-byte allocation. This free call uses original slot 0x10109FF30,
IA diversity 46A2 and address diversity zero. The shared diversity value
alone is not used to identify either function.

The first post-VM-return access to X0 is an overwrite:
`LDR X0,[SP,#1930]` at 0x100541BD0, loading the cleanup owner for free.
Four source-continuation proofs quantify all 64 X0 return-register bits
and all four NZCV bits. They check the complete retained suffix's reads,
writes and indirect edges and establish the same free argument. The four
contexts use first-query false/true, neither later Boolean contribution,
and environments 0/3. Every other entry register and first-read memory cut
is fixed to its retained source-consistent value. These are conditional
return-channel proofs, not all-environment or native call proofs.

Free has no semantic return value. Its private callbacks use X0=0 or
FFFFFFFFFFFFFFFF and explicit caller clobbers. The allocation is marked
retired in the evidence; validation finds no subsequent source read/write
of its 32-byte storage before the final boundary. Retained physical bytes
are labeled a retired storage snapshot, not a live object or native free
effect. The exact post-free stop is before `STR XZR,[X9]` at 0x10057A774,
where X9 is the original B+38 output pointee without a proven native extent.

The retained outer four-byte status remains 74C29D69, independently of the
modeled VM return. Under the observed XOR codec,
`74C29D69 XOR 8B3DC651 = FFFF5B38`. Its symbolic error name and final
publication remain unknown. This status is separate from the nested
allocation-failure status and from the VM API's return register.

## Available-cache fast path, fallback and ports

```text
daemon 1004776C0: libSystem/_vm_deallocate
    |
    | symbol/interface join; native runtime version match unknown
    v
cache _vm_deallocate 18054A0B0
    -> _mach_vm_deallocate 1805497A4
         |
         +-> optional logger call 180549844
         |
         +-> trap -12: SVC 180547A90
                |
                +-> return != 10000003: return status
                |
                +-> return == 10000003
                     -> MIG stub 18056F104
                     -> modeled mig_get_reply_port
                     -> packed call 18056F174
                     -> Mach2 SVC -47 at 180547C1C [stop]

kernel trap table[-12] -> FFFFFE000BCDB4EC
    -> helper(name,0)
    -> helper NULL: return 10000003
    -> load/authenticate field +28; load address/size from argument record
    -> range leaf FFFFFE000BDC1EC0
    -> aligned [start,end) tail interface FFFFFE000BDCAE7C
```

The cache trap veneer at 0x180547A8C executes `MOV X16,#-12; SVC #80`.
The wrapper compares W0 with 10000003. The local SDK independently names
this value `MACH_SEND_INVALID_DEST`. Its presence does not identify which
native lookup or transport state produced it.

The optional logger pointer is at 0x1EB065E48. Its call receives
`(20, low32(task), address64, size64, 0, 0)` in X0..X5. Explicit logger
models clobber caller registers/NZCV and preserve X18..X29; the original
wrapper restores the VM arguments from saved registers before the trap.
No native logger callback or pointer authentication was executed.

| Port/name channel | Source site | Established contract |
| --- | --- | --- |
| Task input | Daemon 100477644; cache X0 input | Daemon loads a u32 task-self word. Cache accepts the supplied task name; it is not a bootstrap, IOKit connection or FairPlay RPC port. |
| Destination task name | Stub 18056F13C, request+08 | low32(task); header requests COPY_SEND disposition 19. |
| Local reply name | `_mig_get_reply_port` call 18056F12C; request+0C | Private helper model supplies a u32 name; header requests MAKE_SEND_ONCE disposition 21. Native helper ownership/lifetime remains unknown. |
| Voucher name | Request+10 | Zero in this request. |
| Fast-trap boundary | SVC 180547A90 | Selector -12, arguments task/address/size in X0/X1/X2. |
| Message request call | BL 18056F174 -> 18055A894 | Prepared inline request passed to `_mach_msg2_internal`. |
| Message emission boundary | SVC 180547C1C | Selector -47 and packed request arguments; all models stop before execution. |

These are source-established conditional emission contracts and specified
dispositions. No native port right, transfer or emission was observed.
Creating a private integer with a port-like value does not establish a right.

## Request, reply and packed-call layouts

The original request has no complex bit or descriptors:

| Request offset | Width, bytes | Field |
| --- | ---: | --- |
| +00 | 4 | msgh_bits=1513 |
| +04 | 4 | msgh_size=48 decimal |
| +08 | 4 | Remote task name |
| +0C | 4 | Local reply name |
| +10 | 4 | Voucher=0 |
| +14 | 4 | ID=4801 decimal (12C1) |
| +18 | 8 | NDR bytes 0000000001000000 from original exported `_NDR_record` |
| +20 | 8 | Address, full u64 |
| +28 | 8 | Size, full u64 |

The stub supplies a 44-byte receive limit. Its normal reply checks expect
ID 4901 decimal (1325), a clear complex bit, msgh_size=36 decimal, and
zero in the four-byte field at reply+08. It then loads the four-byte return
code at reply+20. ID 47 hexadecimal takes a separate status path; other
ID mismatches and malformed normal replies have distinct original error
paths. These checks are statically recovered; these profiles stop at send
and do not synthesize successful received replies.

Let T and R be u32 task/reply names, A/Z full u64 address/size, and M the
request buffer. The prepared call and the intercepted Mach2 boundary agree:

| Register | Value |
| --- | --- |
| X0 | M |
| X1 | 0000000200000003 |
| X2 | 0000003000001513 |
| X3 | (u64(R)<<32) OR T |
| X4 | 000012C100000000 |
| X5 | u64(R)<<32 |
| X6 | 44 decimal |
| X7 | 0 |

Low option bits 3 request send and receive; the high option bits are
retained numerically. The request body's size is 64-bit, while its fixed
message/receive extents are separate framing quantities. A byte-array proof
quantifies all task, reply, address, size and initial memory bits at the
recorded disjoint placement. Constants/NDR are pinned file-data premises.

The incoming receive name is R in high32(X5), produced by the shift at
0x18056F150. The outgoing destination name is T in low32(X3). The same
buffer M carries the 48-byte outgoing request and the bounded reply receive.
This identifies the direction and producer of the two names; their native
numeric values, rights and per-thread ownership remain unknown.

After the packed message helper, the original cleanup gate distinguishes
raw returns {10000002,10000003,10000010} from all other u32 values. This
classification and the reply-ID comparisons have universal local proofs.
Reply-port helper, message-destruction and return paths remain unexecuted
in the request-frontier models.

Compile-only [SDK/layout checks](triage_evidence/daemon_vm_cleanup_sdk.c)
and [LLVM IR](triage_evidence/daemon_vm_cleanup_sdk.ll) verify request 48,
normal reply 36, base trailer 8, and reconstructed kernel argument record
24-byte sizes, plus offsets, disposition values and fallback constant.
The installed SDK is not a matched native target runtime.

## Kernel dispatch and lower range interface

Trap entry 12 in the original table at FFFFFE0007EFB010 specifies three
arguments, five u32 words and no port return. Its handler slot is
FFFFFE0007EFB138, format-8 authenticated target FFFFFE000BCDB4EC,
diversity 307A, address diversity zero. Name/munger pointers and table bytes
are independently re-decoded from original collection chain metadata.
The handler's original parallel name is `_kernelrpc_mach_vm_deallocate_trap`.

| Handler input-record offset | Width, bytes | Original use |
| --- | ---: | --- |
| +00 | 4 | Name passed to helper FFFFFE000BCFB4F0 with second argument zero |
| +04 | 4 | Padding between the observed loads |
| +08 | 8 | Address loaded into X1 before the leaf tail call |
| +10 | 8 | Size loaded into X2 before the leaf tail call |

The name helper's NULL result returns 10000003. Otherwise the handler loads
field +28 from its returned object, conditionally authenticates that pointer
with AUTDA, and passes it as X0 to FFFFFE000BDC1EC0. Its exact runtime object
type, lookup policy, reference ownership and authentication result are
unknown. Here P denotes the resulting leaf argument; the map role is an
inference from this VM interface, not a recovered original structure name.

The original leaf has this ordered control flow:

```text
P == 0                    -> return 4
P != 0 and size == 0      -> return 0
address + size has carry  -> return 4
otherwise read byte(P+2C), align endpoints and compare
end <= start             -> return 4
end > start              -> tail(P,start,end,0,0) at FFFFFE000BDCAE7C
```

For u64 A/Z and the byte Q at P+2C, the exact local equations are:

```text
S    = u64(A + Z)
M32  = NOT_u32(FFFFFFFF << (u32(Q) AND 31))
M    = zero_extend_u32(M32)
start = A AND NOT_u64(M)
end   = u64(S + M) AND NOT_u64(M)
```

The initial ADDS carry rejects unsigned A+Z overflow before the field read.
Rounding uses the source's modular addition, followed by the unsigned
end>start test. The tail receives an end address, not the original size.
Native constraints on Q and the deeper routine's map/locking/ownership
contract remain unknown. The proof covers all 256 Q values; this does not
assert that all are valid native page-shift states.

The two arithmetic fragments have 2,048 private CPU checks: all 256 field
bytes crossed with eight A/Z pairs. They execute ten original instructions
per case, with a private mapped byte and no VM helper call. These component
states are separate from complete kernel paths. Their sum/carry, alignment
and comparison results agree with the universal source equations.

For the daemon's modeled zero address/size, a non-NULL P would select the
leaf's zero-size return. A NULL name-helper result would instead select the
cache fallback value; a non-NULL helper with NULL field+28 reaches leaf
return 4. These are conditional source compositions. Actual task-self
rights, helper results and native reachability have not been observed.
The Mach request's kernel receive-side handler has not been joined to this
fast-trap handler or the lower VM tail.

## Assumptions, validation and remaining interfaces

| ID | Premise / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| VC1 | Daemon image, available-cache UUIDs and collection hash pin the original bytes. | Rehash daemon; match all visited opcodes and compiler function ranges; re-decode used bind/fixup/table words. Do not infer native runtime equality from symbol equality. |
| VC2 | Retained predecessor contexts, declared globals/API outcomes and source-consistent first-read cuts define the daemon proofs. | Preserve 96 prefixes; compare three VM returns, two environments and four Boolean combinations. Universal return/NZCV proofs use four explicitly retained contexts only. |
| VC3 | Modeled allocation extents are valid before the explicit free request; retirement does not execute a native allocator. | Verify the exact owner argument and reject later source accesses; keep retired backing snapshots separate from live objects and native lifetime. |
| VC4 | Cache stack/storage, NDR/constants and callback/trap results are explicit private models. | Fresh independent read/write replay of 30 cases, logger on/off, full-width argument edges and six request frontiers. Native callback, helper and trap state remain unknown. |
| VC5 | Local proof placements are valid/disjoint; other daemon proof registers/memory cuts are fixed. | Byte-array request proof; rebuild every cut and indirect edge; reject symbolic/unavailable source addresses and mismatched reads/writes. |
| VC6 | PAC is logical and integer names do not prove rights. | Pin source PAC instructions, slots and modifiers; distinguish task input, reply helper, message dispositions and kernel pointer authentication. Native namespace/transfer effects remain unknown. |
| VC7 | Kernel range arithmetic uses readable P+2C on the non-NULL/nonzero/nonoverflow route. | All-byte/all-u64 local proofs plus 2,048 CPU cases; zero/NULL branches precede this read. Recover actual map type, page-field invariants and deeper ownership separately. |
| VC8 | Source emission contracts, local zero-size behavior and status equality do not prove native IPC, final admission or publication. | Join a matched runtime and receive-side message handler, then actual output-owner extents, state consumers and final publication. |

All 11 original/simplified proof pairs solve UNSAT; both forms of 22 SMT
files are rebuilt and parsed/solved independently. Four source-continuation
proofs cover all return/NZCV bits under their published cuts; the remaining
proofs cover local full-domain ABI/arithmetic equations. Native branch
feasibility and all-environment coverage are not claimed.

Fresh daemon replay checks 96 profiles / 450,384 source visits, 92,592 reads,
29,568 writes and 13,344 logical edges. It verifies 96 VM-return models and
48 free models, with no post-free access before the stated output frontier.
All private source-read bytes are known. Fresh cache replay independently
checks 30 profiles / 1,206 source/interception visits, 198 reads, 318 writes,
30 intercepted trap boundaries, 21 declared callbacks and six final Mach2
request boundaries. Six fast-trap frontiers stop before a modeled return;
18 cache cases return; six reach the message frontier. Intercepted SVCs and
declared callbacks are not native instructions or IPC effects.

The [kernel component evidence](triage_evidence/daemon_vm_cleanup_kernel_components.json)
adds 20,480 original arithmetic-instruction visits. These counts are
component checks, not additional daemon requests. Source capture includes
seven original cache functions, two original kernel functions, 2,689 unique
daemon instructions, exact bind/table evidence and compile-only SDK checks.

Recovery/replay cost is O(source/artifact bytes + visits + collection bytes
and fixups); space is O(collection metadata + largest profile + one private
CPU map). Symbolic proofs add BV/array expression DAGs and solver resources.
All byte widths and modular equations are exact; no timing, native failure
rate or native performance estimate is inferred.

| Impact | Next investigation | Required evidence |
| --- | --- | --- |
| high | Join request 4801 to its actual kernel message receiver. | Original subsystem table, request-size/type checks, task-right conversion, handler and reply emission. A matching selector/name is insufficient. |
| high | Establish native daemon-to-runtime identity and rights. | Actual loaded libsystem_kernel/cache build, task-self value provenance, reply-port helper ownership and valid namespace rights. |
| high | Continue caller input/parser and final output ownership. | Parent-consistent owned B+0 spans and B+38/B+40 output extents, state/numeric consumers and actual publication. |
| medium | Complete fallback reply/error lifecycle. | Received reply models with source validation, destruction, reply-port deallocation and returned status paths. |
| medium | Recover deeper VM range ownership and synchronization. | Tail routine P/start/end contract, reference/locking transitions, rounding invariants and actual map field provenance. |

QG1: Pass; factual source, ownership, ABI and transport analysis requires no normative judgment.

QG2: Pass for this increment; VC1-VC8 specify premises, dependent results and falsification probes.

QG3: Pass for this increment; daemon cleanup/free, available-cache trap/MIG emission contracts, request/reply layouts and kernel range ABI are covered. The full objective remains incomplete.

QG4: Pass; widths, extents, exact modular arithmetic, reproduction steps, finite counts and complexity are explicit.

QG5: Pass within scope; runtime identities, port integers/rights, private/native effects, cleanup epochs, return/status channels and full versus component paths are separated.

QG6: Pass; original file bytes, exports/nlist/re-exports, chain/table decoding, rebuilt SMT, SDK compile and independent daemon/cache read/write replay support the scoped claims.

QG7: Pass; impact-labeled continuations cover receive-side joins, native rights/runtime identity, caller owners, fallback reply lifecycle and deeper VM ownership.

Publication evidence: [preservation](triage_evidence/daemon_vm_cleanup_delivery.json)
and [scoped quality gates](triage_evidence/daemon_vm_cleanup_quality_gates.json).
