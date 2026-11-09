# Mode471C lock lifecycle, descriptor fields and caller ownership

The continuous mode471C path lazily creates the lock stored at `0x1010C67C0`, requests acquisition and cleanup through the known adapters, and tests a distinct u32 global at `0x1010C67D0`. A preexisting non-NULL lock skips allocation. Under the retained zero-field image premises, all 28 paths publish raw body result `0x74C29F00`, return through the entry and cursor adapter, and pass the eight-byte input owner to `free` at `0x10039C988`. They stop before an unknown-dependent caller-frame dereference at `0x10039C998`.

This increment extends the [record/cursor report](daemon_descriptor_producers_report.md); it does not establish native incoming phases or a daemon-to-kext message for mode471C. The full daemon/kext/deeper-interface investigation remains active. Original bytes, modeled imports, arbitrary-byte symbolic flow and fresh A64 execution have separate provenance. The attempted fresh IDA readback failed because its authenticated Assist worker was unavailable; **zero fresh IDB bytes** are claimed here.

Evidence: [source and contracts](triage_evidence/daemon_mode471c_lifecycle_contracts.json), [28 continuous paths](triage_evidence/daemon_mode471c_lifecycle_profiles.json), [ten proof pairs](triage_evidence/daemon_mode471c_lifecycle_proofs.json), [112 A64 replays](triage_evidence/daemon_mode471c_lifecycle_replays.json), [independent checks](triage_evidence/daemon_mode471c_lifecycle_checks.json), [SDK assertions](triage_evidence/daemon_mode471c_lifecycle_sdk.c), [failed IDA readback](triage_evidence/daemon_mode471c_lifecycle_live_ida.json), [preservation](triage_evidence/daemon_mode471c_lifecycle_preservation.json), and [scoped quality gates](triage_evidence/daemon_mode471c_lifecycle_quality_gates.json).

## Assumption register

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| ML1 | Addresses refer to thin arm64e SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. | Rehash source, compare 14 spans, every retired opcode, 110 fixups and seven dispatch slots. Fresh IDB corroboration is unavailable. |
| ML2 | The preceding caller entry, private frame, pointer/counter and bank/controller premises apply. Native reachability remains unknown. | Continue the actual preceding prefix without fixture PC transitions; vary two placements and controller pairs. |
| ML3 | Caller SP+A28/A30 contain source-derived bank roots. | Verify original unconditional stores at `0x100387E50`/`0x100387E64` under X26=POOL; verify the two pool words and biases. These are initial state fixtures, not a claim that the producer executed continuously into the selected caller. |
| ML4 | File-backed bytes, logical fixups and declared overrides define initial image state; other mapped image bytes are private zero fixtures. | Record all source writes; test initially NULL and non-NULL lock cells. Native evolved state, publishers and concurrency remain unknown. |
| ML5 | malloc/init/once/lock/unlock/free return under explicit ABI models. | Compile actual SDK signatures/extents; retain arbitrary volatile GPR/SIMD/NZCV and opaque objects. Check targets, modifiers, arguments and preserved registers in each replay. Native implementations do not execute. |
| ML6 | A returned allocation or preexisting lock denotes an opaque 200-byte private owner. | Keep all object bytes arbitrary; permit the source eight-byte clear before initialization; invalidate all object bytes after each modeled operation. Native owner validity and lifetime are unknown. |
| ML7 | The input denotes an eight-byte owner; prior unspecified frame bytes remain arbitrary. | Preserve 1,232 private-byte origins across the cases, retain the decoded word, retire the input at free and reject subsequent reads. Native allocation-to-use provenance is unknown. |
| ML8 | Once is initially completed or invokes its callback once and returns. | Exercise both states, two API-private frame gaps (256/512 bytes), original callback instructions and its leaf; verify callback SP/callee preservation. Callback invocation is an explicit library model transition, not an original direct daemon branch. |
| ML9 | Pointer authentication is a logical target/token abstraction. | Check original slots, modifiers, branch registers, return tokens and SP restoration. Native PAC success is unknown. |
| ML10 | Record addresses satisfy the acquisition key's eight-byte alignment premise. | Check actual records; prove the key under R&7=0 and retain a satisfiable premise witness. No weaker alignment is asserted. |
| ML11 | The tested field is zero in the retained writable-image states. | Prove the full-u32 zero/nonzero branch partition; preserve the nonzero entry's original bytes. A populated registry is not executed in these cases. |
| ML12 | Primitive calls return without modeled concurrency; their status is 0 or 22 in the finite cases. | Reuse the independently established adapter control contracts; compare eight acquisition/cleanup request pairs. Actual native lock acquisition and pointer stability are unknown. |
| ML13 | XOR result interpretation uses the previously established 32-bit convention. | Verify the raw store independently: `0x74C29F00 XOR 0x8B3DC651 = 0xFFFF5951`, signed32 -42671. A symbolic error name is unknown. |
| ML14 | The supplied RAX log is historical emulated trace evidence. | Rehash it against the retained packet audit. RAX producer version and historical library UUID attestation remain unknown; the trace does not establish a native mode471C emission. |

## Control and ownership sequence

```text
caller39C894 -> cursor adapterABCA64 -> entryA59BB4
  |
  +-- unmask opaque word, then preserve U at callee SP+3630
  +-- test lock cell1010C67C0
  |     +-- non-NULL: reuse captured pointer
  |     +-- NULL: creator43A240 -> malloc(200)
  |                 -> clear first8 bytes -> pthread_rwlock_init(pointer,NULL)
  |                 -> status0 publishes pointer at2097DC
  |
  +-- eligible pointer -> acquire43E280
  |                        -> pthread_once(control1010B8CD0,callback40EBD4)
  |                        -> pthread_rwlock_wrlock(pointer)
  |
  +-- common handlerB353A4 -> read u32[1010C67D0]
  |       zero -> initial body result74C29F00 retained
  |       nonzero -> key-search entry8BF64C (inspected, not executed here)
  |
  +-- eligible pointer -> cleanup4423F8 -> once -> unlock
  +-- store body result at input record+16; restore SP/cursor delta0
  +--39C988 -> free(eight-byte input pointer)
  +--39C998 -> STOP before dereference through unknown caller SP+5B0 value
```

Creator failure paths reach the common zero-field handler without an acquisition or cleanup request. Successful creation and preexisting-pointer paths each request one write lock and one unlock. These are source requests under ML1-ML12, not evidence that a native lock was held. Six initially-NULL allocation/init categories times two placements times two once states give 24 cases. The preexisting-pointer path has no applicable allocation outcomes and contributes four cases. Four of the 28 execute the original callback through the explicit once model.

## Status gate and stack-slot epochs

The same stack address has different lifetimes. `0x1009D0304` writes the decoded opaque u64 D to callee SP+2A70. `0x1009F0168..0x1009F016C` reads D and XORs the source-derived mask0xE3B88695C0D52DBC; `0x100975790` stores the resulting U to SP+3630. Thus U=`BE64(input8) XOR0x9898989898989898`. This corrects the earlier copy description; see the [registry lookup report](daemon_registry_lookup_report.md). **`0x100972914` then stores only u32 `0x471C` at SP+2A70** on the creator path. Thus the later `0x1009729F0` load sees the mode, not low32(D). The status comparison is ordinary encoded success: raw creator result `0x8B3DC651` and a non-NULL cell select table index447C; any other combination selects51D7. The original table targets are `0x100933C2C` and `0x100C02F3C`. A later post-acquisition index40C7 also targets `0x100C02F3C`; shared physical destinations do not equate their incoming states.

| Declared creator outcome | Raw creator result | Publish to lock cell |
|---|---|---|
| malloc NULL | `0x74C29D85` | No |
| init0 | `0x8B3DC651` | Yes, at `0x1002097DC` |
| init12 | `0x74C29D85` | No |
| init16 | `0x74C29D82` | No |
| init22 or initFFFFFFFF | `0x74C29D83` | No |
| Preexisting pointer | Creator skipped | No creator write |

These creator results differ from the final zero-field body result `0x74C29F00`, observed in all 28 cases. No native errno interpretation is assigned. Failed-initializer allocations have no free in the retained suffix; eventual cleanup beyond the stop boundary and native lifetime are unknown.

## Adapter and imported ABI

R2 is reused with different layouts. Acquisition uses encoded control at R2+0 and captured pointer at+8; its key is `u32((low32(R2) XOR 0x987EAC8A)*0x316F29C1)` and decoded control is593D. Cleanup uses the freshly selected pointer at R2+0 and encoded control at+8; its key is `u32((low32(R2) XOR 0xEAAE0AC9)*0x7398180B)` and decoded control isA293. The cleanup caller rereads the global in source order before packing its record; stable private fixtures do not prove equality under concurrent mutation. R2's minimum accessed extent is20 bytes during creation and12 bytes for each later adapter record.

| Source call PC | Original slot | Target or import | IA modifier |
|---|---|---|---|
| `0x100933CD0` | `0x10109FE88` | acquire `0x10043E280` | 6AA4 |
| `0x100A2051C` | `0x10109FC08` | cleanup `0x1004423F8` | 6AA4 |
| `0x10019385C` | `0x10109FF58` | malloc | 6AA4 |
| `0x100130FCC` | `0x1010A0DD0` | pthread_rwlock_init | A027 |
| `0x10043E508`, `0x100442650` | `0x10109FE80` | pthread_once | 8489 |
| `0x100361DF4` | `0x1010A0A00` | pthread_rwlock_wrlock | 4C4D |
| `0x100208EFC` | `0x1010A0D78` | pthread_rwlock_unlock | 5431 |
| `0x10039C988` | `0x10109FF30` | free | 46A2 |

SDK compile assertions establish pointer/size_t8 bytes, int4 bytes, pthread_once_t16 bytes, pthread_rwlock_t200 bytes and exact function signatures for this SDK. Volatile state, full void-return X0 and int-return upper32 bits remain arbitrary. The source free suffix does not use X0 before the unresolved load. Callback frame transitions and imported effects are explicitly marked in the journals; no native library body is substituted into the daemon source visit count.

## Data-flow frontiers and IPC implications

| Global/interface | Established use | Remaining unknown |
|---|---|---|
| `0x1010C67C0` | Lock storage-pointer cell; lazy publication | Native publisher path, validity, concurrency |
| `0x1010C67D0` | u32 zero/nonzero field tested at `0x100B353C8` | Native count/availability meaning and producer |
| `0x1010C67A8` | Pointer loaded for nonzero-field search | Allocation, population, extent, concurrency |
| `0x1010C9288` | Payload-base pointer; index scaled by32 bytes | Payload type, owner, downstream use |
| Search `0x100BB01E8` | Adds zero-extended u32 index*16; reads u32 at entry+8 | Complete key predicate and positive/negative native paths |
| Caller SP+5B0 | Loaded at39C994 then used as address at39C998 | Incoming source definition and target lifetime |

No common C structure is inferred from address proximity. These globals are distinct from prior descriptor G=`0x1010C8218`, whose established records have48-byte stride. On the zero-field path the initial index is0; the source handler propagates an existing non-success status regardless of base, and only generates a candidate payload pointer for encoded-success input. Full-width source theorems retain both status/base categories.

No new original Mach send, receive, port-right transfer, message ID or IOKit emission site is established in these paths. The names471C/593D/A293 and local table indices are internal controls. Imported internals and unresolved successors are outside that conclusion. The [annotated RAX packet audit](triage_evidence/zut_trap_argument_audit.json) remains applicable to the unchanged trace SHA-256 `78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e`:27 printed Mach2 records,22 matched sends and44 printed hex headers. It does not connect mode471C to a packet by itself. See the [trap interface report](user_trap_interface_report.md) for packet register versus message-body contracts.

## Validation, reproduction and bounded continuation

| Check | Coverage |
|---|---|
| Continuous symbolic source | 28 cases,34,616 continuation visits,1,232 private-byte origins and73,040 disjoint API-byte origins |
| Independent A64 | 112 cases,188,192 source visits,37,328 read effects,13,616 write effects,4,864 logical edges,416 modeled API returns and16 callback invocations/returns |
| Fresh checker replay | Two additional full source compositions |
| Source proofs | Ten pairs:20 UNSAT queries,103 lifted instructions,one nonempty alignment premise witness;28 additional opaque-word writer/reader equivalence checks |
| Original provenance | 14 spans,110 fixups,three exhaustive byte-bank identities (768 inputs),seven dispatch slots,two source-derived roots |
| Instruction coverage | 1,861 distinct retired continuation opcodes;one separately inspected unretired boundary opcode |
| SDK/trace | Compile exit0,two rehashed headers,unchanged supplied trace and prior packet audit |
| Fresh IDB | Unavailable bridge;zero bytes verified |

```sh
export PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages
export Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_mode471c_lifecycle.py
```

Published outputs are frozen evidence. The checker is read-only with respect to the source binary, original triage inputs, IDBs and native APIs; it writes its own check JSON. Producers, fresh replays and proof construction are linear in retained visits/events/expression DAG size apart from solver work (30 s limit/query); replay RAM is bounded by the private mapped owners and largest trace. Byte counts denote storage extents, not elapsed time.

| Impact | Next bounded investigation | Discriminating evidence |
|---|---|---|
| High | Recover native publishers of the three field/base globals. | Continuous stores and owner extents can establish a populated-state premise, then permit nonzero lookup/copy analysis. |
| High | Recover caller SP+5B0 definition along the actual incoming phase. | Source-order def-use proof resolves39C998 without an arbitrary target fixture. |
| High | Connect resulting payload consumers to retained Mach/IOKit request producers. | A continuous record-to-message path with exact byte offsets can link this local interface to kext transport. |
| Medium | Characterize explicit populated-registry input fixtures after owner bounds are recovered. | Separate conditional key matches/misses from native population evidence. |
| Medium | Inspect concurrent pointer mutation and failed-init allocation cleanup. | Native or source lifetime evidence distinguishes transient local state from eventual ownership. |
| Low | Refresh IDB windows when the bridge is available. | Raw source agreement adds database corroboration; it does not establish native execution. |

## Scoped quality gates

QG1 passes for factual technical analysis. QG2 is covered by ML1-ML14 and their probes. QG3 passes for this lifecycle increment; the full objective remains incomplete. QG4 covers explicit u32/u64 arithmetic, byte extents, SDK signatures and complexity bounds. QG5 separates creator/body status, stack-slot epochs, record layouts, global cells, modeled/native effects and the exact unresolved frontier. QG6 covers original bytes/fixups, independent A64 execution, solver files, SDK and trace hashes, with unavailable IDA evidence explicit. QG7 is covered by the impact-bounded continuation table.
