# SIDB pathname removal, object-field zeroing and SIDN handoff

After the repeated SIDB `lstat` request established in the [word-routing report](daemon_state_word_routing_report.md), the retained source distinguishes zero from nonzero return values. A zero result demands a fresh two-byte mode word. Link-type controls advance to the SIDN object; all other retained modes request `unlink` on the SIDB pathname. A zero unlink return leads through write-lock/unlock requests, writes zero to two SIDB u64 fields, and then advances to SIDN. Nonzero lstat and unlink controls also advance to SIDN, with the raw status distinctions below. These are conditional original-source paths, not observed filesystem outcomes. [PR1-PR6; PR-A1-PR-A7]

```text
pending lstat(SIDB+32, oldSP+40)
  + declared int return; invalidate stat[144] and errno[4]
  |
  +-- nonzero -> ___error -> demand errno32
  |                            +-- 2     -> raw 74c29dd1 --+
  |                            +-- other -> raw 74c29dd3 --+
  |                                                       |
  +-- zero -> demand mode16 at oldSP+44                    |
               +-- (mode & f000) == a000 -> raw 74c29dd3 --+
               +-- other -> unlink(SIDB+32)               |
                              +-- nonzero -> 74c29dd3 ---+
                              +-- zero                   |
                                  once -> wrlock         |
                                  SIDB+8,+16 := u64 zero  |
                                  once -> unlock         |
                                  raw 8b3dc651 ----------+
                                                        v
              caller record: control 8e81a596, object SIDN
                    -> same three adapter entries
                    -> ___error; errno32 := 0
                    -> lstat(SIDN+32, newSP+40) pending
```

The two zeroed fields were already zero in these incoming states. The source writes and their local all-pointer equation are established; a nonzero-to-zero transition, pointer retirement or cache eviction is not established. The retained 4096 B buffer owner remains present, with exactly its four previously supplied prefix bytes defined. No buffer free, native lock acquisition, native unlink, native Mach-port emission or daemon-kext transaction is established by this increment. [PR1-PR6; PR-A2-PR-A7]

| Evidence | Primary artifact and scope |
| --- | --- |
| PR1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; original bytes/fixups retained by the [extractor](triage_evidence/recover_daemon_state_path_removal.py). |
| PR2 | [Word-routing checks](triage_evidence/daemon_state_word_routing_checks.json.zst): incoming pending-lstat cases 0,2,21,23; two prior ABI patterns crossed with raw prefix words 0 and 0x7000c. |
| PR3 | [Current checks](triage_evidence/daemon_state_path_removal_checks.json.zst): 224 intervals, 76 pending SIDN queries, explicit API/scalar premises and exact byte-definedness journals. |
| PR4 | [Auditor](triage_evidence/audit_daemon_state_path_removal.py) and [audit](triage_evidence/daemon_state_path_removal_audit.json.zst): independent instruction replay, complete state joins, status stores, owner preservation and ten nonvacuous source equations. |
| PR5 | [Compile-only ABI probe](triage_evidence/daemon_state_path_removal_abi.c): current arm64e SDK prototypes, mode/errno constants and opaque extents; source, assembly and SDK-relative header hashes retained in PR3. |
| PR6 | [Publication verifier](triage_evidence/verify_daemon_state_path_removal_publication.py): rebuilt equations, original-byte/fixup checks, eleven original Mach-O site brackets, exact coverage/delta, path hygiene and preserved inputs. |

## Result, mode and errno partitions

The modeled SIDB query has SP=`0x680005ff10`, output address `0x680005ff38` and pathname pointer `0x6600006020`. Every declared lstat return invalidates the entire current-SDK 144 B output span and the four borrowed errno bytes. The successful return stops before `LDRH W8,[SP,#0x2c]` at `0x1003795d4`, with both demanded bytes undefined. Nonzero controls stop at the separate errno-accessor request; returning its borrowed pointer stops again before the undefined four-byte read at `0x1005797c8`. Stale private stack backing and the earlier source-written errno zero are never treated as new output. [PR1-PR6; PR-A2-PR-A5]

| Original source fragment | Exact local partition under recorded scalar phase | Dispatch / raw result |
| --- | --- | --- |
| 0x1004cd198..0x1004cd1b0 | W0==0 versus W0!=0 | Index 0x5fdd versus 0x5f61; zero reaches mode demand, nonzero reaches ___error at 0x1005797c4 |
| 0x1003795d4..0x1003795f8 | (mode16 AND 0xf000)==0xa000 | Index 0x322c for link type, otherwise 0x3203; link branch carries 0x74c29dd3 |
| 0x1005797c8..0x1005797e8 | errno32==2 versus other | Raw u32 0x74c29dd1 versus 0x74c29dd3 |
| 0x100628154..0x100628178 | W0==0 versus W0!=0 after unlink | Index 0x1d41 versus 0x1d47; nonzero carries 0x74c29dd3 |

The source equations cover every u32 return/errno value and every u16 mode under the verified phase constants. At the lstat result fragment W20=`0x5f61`, W24=`0x1d47`; at mode demand W9=`0x3203`; at errno demand W20=`0xc69c`; at unlink return W25=`0xc4b7502a`, W27=`0xc69c`, W24=`0x1d41`. The auditor checks these 152 concrete seed-register occurrences in the retained source frames. Universal local equations do not extend the complete SIDN-handoff traces to other incoming private states. [PR1,PR3,PR4,PR6; PR-A1-PR-A5]

The four int-return controls are 0,0xffffffff,1,0x80000000; the positive and unusual high-bit controls are explicit perturbations, not a claim about the documented native return set. Mode controls are 0,0x81a4,0x41ed,0xa000,0xa1ff,0xffff. Both link-type controls advance directly; the other four request unlink. Thus the observed predicate is a link-type test, not a regular-file-only test. Errno controls are 0,2,13,0xffffffff after each of the three nonzero lstat controls. The current SDK defines ENOENT=2, S_IFMT=0xf000 and S_IFLNK=0xa000; historical runtime equivalence remains unknown. [PR3-PR6; PR-A3-PR-A5]

The pending unlink is at `0x100628150`, IA `0x566a`, X0=`0x6600006020`, the source-carried `/var/db/fpsd/SC Info/SC Info.sidb` path. Nonzero unlink returns advance without a new errno-word demand on these retained paths. The raw status words are stored in private records; they are not assigned POSIX errno values, public API returns or final daemon-response meanings. [PR1-PR6; PR-A4-PR-A7]

## Synchronization requests and exact object writes

Only the selected non-link mode 0x81a4 continues through the unlink-return matrix. Its zero-return path calls `0x100628a24 -> 0x10043e280`, IA `0x6aa4`, with a private record at `0x680005ffd0` carrying the SIDB object's lock pointer L=`0x6600007000`. After the declared write-lock return, `STP XZR,XZR,[X19,#8]` at `0x100628a28` emits two eight-byte zero writes to B+8 and B+16, where B=`0x6600006000`. It then calls `0x100628acc -> 0x1004423f8`, IA `0x6aa4`, using the reused private record for cleanup. [PR1-PR6; PR-A2-PR-A6]

| Pending site | Imported interface / IA | Source arguments |
| --- | --- | --- |
| 0x10043e508 | pthread_once / 0x8489 | X0=0x1010b8cd0; X1=0x10040ebd4 |
| 0x100361df4 | pthread_rwlock_wrlock / 0x4c4d | X0=L=0x6600007000 |
| 0x100442650 | pthread_once / 0x8489 | Same once control and callback |
| 0x100208efc | pthread_rwlock_unlock / 0x5431 | X0=same L |

Each synchronization sequence supplies status 0 or 35 to all four interfaces. The paired sequences have identical original instruction visits. Once returns invalidate all 16 current-SDK control bytes and explicitly assume completion without additional callback effects; lock/unlock returns invalidate all 200 current-SDK L bytes. The source intervals neither read nor write these opaque spans. This checks source pointer pairing and finite status perturbations; it does not establish native successful locking, the full return domain or actual callback scheduling. The original callback is not newly invoked in this increment. [PR3-PR6; PR-A3,PR-A4,PR-A6]

The zero stores leave the carried SIDB pathname, undefined object gaps, other preserved SIDB/SIDN fields, buffer owner and generated 32 B field at J+0x34 unchanged. Zeroing already-zero fields does not demonstrate release of an allocation. The all-pointer local equation verifies the store addresses and zero values independently of prior field contents; alternate nonzero incoming fields are outside the full-path matrix. [PR1,PR3,PR4,PR6; PR-A2,PR-A6,PR-A7]

## Raw status channels and the distinct SIDN request instance

| Retained SIDB outcome | Adapter output store at 0x1004af644 | Outer caller store at 0x10041ac4c |
| --- | --- | --- |
| Nonzero lstat, errno32=2 | u32 0x74c29dd1 at 0x68000600d0 | Same u32 at 0x6800070dc8 |
| Nonzero lstat, other supplied errno | u32 0x74c29dd3 at 0x68000600d0 | Same u32 at 0x6800070dc8 |
| Supplied link-type mode | u32 0x74c29dd3 at 0x68000600d0 | Same u32 at 0x6800070dc8 |
| Nonzero unlink | u32 0x74c29dd3 at 0x68000600d0 | Same u32 at 0x6800070dc8 |
| Zero unlink, declared synchronization sequence | u32 0x8b3dc651 at 0x68000600d0 | Same u32 at 0x6800070dc8 |

The adapter store is record+8; the outer caller store is record+16. The next outer preparation writes u32 control `0x8e81a596` at `0x6800070db8` via `0x100863f38`, then writes D=`0x6600008000` at record+8 via `0x100863f3c`. These are separate slots and roles. The same reused record address does not make a raw status, request control and object pointer interchangeable. [PR1,PR3,PR4,PR6; PR-A2,PR-A5,PR-A7]

| Call site -> entry | IA | First argument / role in retained handoff |
| --- | --- | --- |
| 0x100863fa4 -> 0x10041a980 | 0xb69a | Outer record 0x6800070db8; contains SIDN object D |
| 0x10041ac34 -> 0x1004946d8 | 0xf248 | Adapted record 0x68000600c8 |
| 0x100494920 -> 0x100493f38 | 0x4e06 | Same adapted record |
| 0x1004cd11c -> imported ___error | 0x6e96 | Declared return reuses borrowed E=0x6600020000, extent 4 B |
| 0x1004cd194 -> imported lstat | 0xf401 | D+32 and newSP+40; pending |

The borrowed-pointer return causes `0x1004cd120` to write errno32=0 and `0x1004cd124` to save D at newSP+16. Source then constructs the inline path and output address. The SIDB and SIDN requests use the same imported call site but distinct object, SP and output addresses. [PR1-PR6; PR-A2-PR-A7]

| Request instance | Object | Inline pathname pointer | SP | Stat output pointer |
| --- | --- | --- | --- | --- |
| Incoming repeated SIDB query | 0x6600006000 | 0x6600006020 | 0x680005ff10 | 0x680005ff38 |
| New pending SIDN query | 0x6600008000 | 0x6600008020 | 0x680005fef0 | 0x680005ff18 |

The second source-carried path is `/var/db/fpsd/SC Info/SC Info.sidn`, including its terminal NUL. The model's 32 B SP difference is exact for these retained request instances; it is not a general stack-frame-size assertion. Reusing PC 0x1004cd194 therefore does not indicate recursion on SIDB. No SIDN lstat return or output bytes are supplied. A future continuation must invalidate its own 144 B output span and errno bytes before introducing any new output. [PR1-PR6; PR-A2-PR-A7]

The original LC_FUNCTION_STARTS table has 1005 advertised entries, 1864 B at file offset 17603576, SHA-256 `ce02892286eaa20b5ad18e05d3a348a5c4b20ab49c668be14fd9e2eb119ccd54`. Eleven new site brackets are recovered directly from it. Entries 0x10043e280 and 0x1004423f8 are advertised starts; the remaining inspected call/store fragments are not. No exact-site original symbols are present. Conditional roles such as "write-lock adapter", "status propagation" and "SIDN request preparation" refer to the demonstrated paths; complete function chunks, original semantic names and all callers remain unknown. IDA was unnecessary for these claims because the pinned image and retained inputs were sufficient. [PR1,PR3,PR4,PR6; PR-A1,PR-A2,PR-A7]

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PR-A1: Pinned image and logical authenticated fixups apply | All original sites, control equations and bindings | Verify source SHA, every retained opcode, fixup word/target/modifier and original Mach-O brackets; hardware PAC remains outside the model. |
| PR-A2: Four retained parent states are conditional entries | Full SIDB-to-SIDN continuations and preservation claims | Exact GP/Q/NZCV/SP/owner/known-byte joins; cross both word routes and prior ABI patterns; no transfer claim for the other 1539 pending parents. |
| PR-A3: Current arm64e SDK supplies comparison ABI and extents | 144 B stat, 16 B once, 200 B lock; mode/errno terminology and imported prototypes | Recompile static assertions and unlink assembly; verify SDK-relative header hashes; historical runtime identity unknown. |
| PR-A4: Declared API returns and opaque effects apply | Return routing, undefined outputs, synchronization and borrowed errno accessors | Invalidate complete spans before continuation; check 152 API-return joins, callee-saved state, integer upper-half perturbations and separate Q/NZCV patterns; no native operation inferred. |
| PR-A5: Mode/errno words are explicit scalar controls and phases are fixed | Universal local predicates and finite raw-status propagation | Demand undefined bytes first, supply only 2/4 B, verify 152 seed-register occurrences and 72 scalar-state joins; rebuild all-u16/u32 equations and preserve synthetic-control labels. |
| PR-A6: Selected mode 0x81a4 and once completion without extra callback effects apply | Write-lock/unlock request sequence and two zero stores | Cross status 0/35, invalidate opaque spans and check exact traces/writes; fields already zero, alternate fields and native callback/lock behavior unknown. |
| PR-A7: Pending requests and raw records do not establish native effects or final meanings | File identity, status semantics, ownership and IPC boundaries | Preserve pending SIDN lstat and buffer owner; require independent native correlation and downstream consumers for file removal, ownership retirement, public status or daemon-kext pairing. |

## Reproduction, coverage and bounded continuation

Checks logical SHA-256: `0e62dbdb1446e6751b3912b53e136bc467e249b8dacd2615960d9ab80ec83fb1`. Audit logical SHA-256: `195067aac1f44f3eb7e7d02cc3e9bf79fd22f144ed85812a30ee7e4b9d8712b3`. Both receipts and the manifest are compressed with `zstd --ultra -22 -q -T1`. Published sources, reports, decoded receipts and decoded hexadecimal payloads exclude analyst-local paths. Target-defined state-file paths are retained as technical evidence. [PR3-PR6]

The extractor continues exactly four of 1543 pending lstat parents, not a claimed equivalence class of all parents. Per parent: 4 lstat returns + 6 modes + 3 errno accessors + 12 errno words + 4 unlink returns + 8 synchronization returns + 19 SIDN pointer returns = 56 intervals; 4*56=224. Counts are 16 lstat cases, 24 modes, 12 errno accessors, 48 errno words, 16 unlink controls, 8 synchronization sequences and 76 pending SIDN queries. The retained journals contain 51832 source visits, 11956 reads, 3780 writes, 780 logical edges and 240 internal calls. [PR2-PR4,PR6]

Independent replay checks 1665792 scalar register values, 1665792 vector register values, 52056 flag states, 67112 read B, 28672 write B and 536 original authenticated edges. Exact joins include 152 imported returns and 72 scalar insertions; the contracts check 152 raw status stores, 76 SIDN record handoffs, 8 paired lock/unlock pointers and 128 zero-store B across alternative cases. Repeated checks are coverage counts, not distinct native events or aggregate native storage. [PR3,PR4,PR6]

Ten equations cover lstat and unlink all-u32 dispatch indices, all-u16 mode dispatch, all-u32 errno raw status, all-pointer two-u64 zero stores, both status-output stores, next-object record construction, errno clear/inline path and lstat arguments. Solver limit is 30 s/query. Arithmetic uses exact u16/u32/u64 widths and byte offsets. Extraction is O(parent bytes+retained visits+effects) time/storage; independent replay is O(V*(register state+effects)+owner joins+query DAG) time and O(receipts+largest interval+known byte map) storage. No native timing is measured. [PR1-PR6]

| Impact | Next evidence | Architectural purpose and present limit |
| --- | --- | --- |
| High | SIDN metadata/result continuation and subsequent file-family steps | Establish whether the same adapter family applies across distinct state objects; current SIDN lstat is pending. |
| High | Outer caller consumers of the three raw statuses | Recover actual aggregate result policy; advancement to SIDN alone does not establish that errors are ignored globally. |
| High | Native trace correlation by object/path, call instance, descriptor and epoch | Distinguish source requests from file identity/removal and identify any later daemon-kext transport; same PC alone cannot pair events. |
| Medium | Nonzero object fields and complete ownership consumers | Distinguish zero-store operation from actual retirement or invalidation; inherited fields here are already zero. |
| Medium | Remaining 1539 incoming states and alternative non-link modes after unlink | Broaden finite full-path coverage without extrapolating from local bit-vector proofs. |
| Medium | Once callback effects, runtime ABI and lock acquisition outcomes | Resolve imported scheduling and historical opaque-layout premises. |

**QG1** passes: factual source/ABI analysis. **QG2** passes: PR-A1-PR-A7 state dependencies and falsification probes. **QG3** passes for this removal/status/next-object increment; the full interface goal remains active. **QG4** passes: exact widths, byte extents, control counts and complexity. **QG5** passes: already-zero fields versus retirement, link type versus regular-file policy, local equations versus finite traces, source requests versus native effects and same PC versus distinct objects remain separated. **QG6** passes after independent replay, ten rebuilt equations, compile/source/provenance checks and exact publication verification. **QG7** passes: bounded expansion covers next objects, status consumers, native correlation, ownership, remaining states and synchronization/runtime identity.
