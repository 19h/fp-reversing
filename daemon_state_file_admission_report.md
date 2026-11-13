# SIDB metadata admission, synchronization and open ABI

The recovered SIDB consumer checks the `lstat` result, reads only a two-byte mode word for metadata admission, and tests its type bits against the symbolic-link value. The selected non-link continuation requests a per-object read lock and matching unlock, updates object+28, clears errno again and requests `open` on the SIDB inline pathname with flags`0x110`. The current arm64e SDK identifies those flags as `O_RDONLY | O_SHLOCK | O_NOFOLLOW` and places the supplied zero variadic argument on the stack. These are conditional original-source and compile-only ABI results; no filesystem operation, lock acquisition, native epoch join or daemon-kext delivery is observed. [SF1-SF6; SF-A1-SF-A8]

```text
pending lstat(SIDB_path, stat_buffer)
  + declared int return; stat[144] and errno[4] become unknown
  |
  +-- result != 0 -> ___error() -> unknown errno word
  |                  + supplied errno: 2 -> status74c29dd1
  |                                    other -> status74c29dd3
  |                  -> common pending malloc(64)
  |
  +-- result == 0 -> unknown mode16 at stat+4
                     + supplied mode
                     +-- (mode & f000) == a000 -> status74c29dd3
                     |                            -> pending malloc(64)
                     +-- otherwise -> pthread_once -> rdlock(SIDB_lock)
                                      -> object+8 zero-field route
                                      -> pthread_once -> unlock(SIDB_lock)
                                      -> object+28 = ffff5b81
                                      -> ___error -> source errno zero
                                      -> open(SIDB_path,110, stack_zero)
                                         [pending; no descriptor supplied]
```

The complete lock-to-open continuation uses mode`0x81a4` and the inherited zero u64 at object+8. Other retained non-link mode controls stop at the first once request. All-bit mode dispatch is proved separately; no native file-type observation is inferred from a supplied control word. [SF1-SF4; SF-A5-SF-A7]

| Evidence | Primary artifact and scope |
| --- | --- |
| SF1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [extractor](triage_evidence/recover_daemon_state_file_admission.py) retains opcodes, logical fixups, GP/Q/NZCV/SP states and byte events. |
| SF2 | [Path-family report](daemon_state_path_family_report.md), [checks](triage_evidence/daemon_state_path_family_checks.json.zst) and [audit](triage_evidence/daemon_state_path_family_audit.json.zst): sixteen exact pending SIDB lstat states and complete object masks. |
| SF3 | [Current checks](triage_evidence/daemon_state_file_admission_checks.json.zst):32 contexts, metadata/errno definedness cuts, scalar output controls, callback variants and pending open requests. |
| SF4 | [Independent auditor](triage_evidence/audit_daemon_state_file_admission.py) and [audit](triage_evidence/daemon_state_file_admission_audit.json.zst): independent instruction replay, complete state joins, output invalidation and eight nonvacuous source equations. |
| SF5 | [Compile-only ABI probe](triage_evidence/daemon_state_file_admission_abi.c), retained source/assembly and canonical SDK-relative header hashes in SF3; [earlier callback analysis](daemon_network_gate_report.md) provides the controller-update equation rebuilt here. |
| SF6 | [Publication verifier](triage_evidence/verify_daemon_state_file_admission_publication.py): exact coverage, fresh contracts/equations/SDK comparison, packed-payload hygiene, preserved inputs and publication delta. |

## Output invalidation and exact metadata predicates

The inherited pending lstat site is `0x10063c368`, IA`0xf401`, with path pointer`0x6600006020` and output address S=`0x680005fed8`. The current SDK comparison establishes a144 B `struct stat` extent, mode offset4 and mode width2. Historical target/runtime layout equivalence remains an explicit premise. Every modeled lstat return removes all144 output-byte definitions and all four errno-byte definitions, including old private fixture fragments and the private known-byte mask. No old stack value becomes a library output. [SF1-SF5; SF-A1-SF-A4]

Source `0x10063c36c..0x10063c384` partitions the entire u32 result domain at zero. Index`0xb2de` selects`0x100617314` for zero; index`0xb30c` selects`0x100622244` for every nonzero value. Concrete controls are0,`0xffffffff` and1. The positive value1 is a return-register perturbation, not a native lstat outcome. Result0 stops before `0x10061734c`, `LDRH W9,[SP,#0x1c]`, demanding exactly S+4..S+5 with an all-unknown mask. Nonzero results request `___error` at`0x1006222d0`, IA`0x6e96`, before any supplied metadata is consumed. [SF1-SF4; SF-A3-SF-A5]

Supplying only the two-byte mode word resumes `0x10061734c..0x100617370`. The recovered mask is exactly`0xf000`; the comparison is exactly`0xa000`. The all-u16 equation covers every permission/type-bit combination under the recorded phase. Index`0x8105` selects the matching branch and`0x80a7` the other branch. No regular-file-only predicate is established by this mode check. [SF1-SF5; SF-A5]

| Supplied mode16 | Type-mask match | Retained next boundary |
| --- | --- | --- |
| 0x0000 | No | pthread_once at0x10041a59c |
| 0x81a4 | No | Same once; selected for full open continuation |
| 0x41ed | No | Same once |
| 0xa000 | Yes | malloc(64) at0x100710758 |
| 0xa1ff | Yes | Same malloc(64) |
| 0xffff | No | pthread_once at0x10041a59c |

The SDK defines `S_IFMT=0xf000` and `S_IFLNK=0xa000`; that supplies the symbolic-link terminology, separately from the original source's numeric predicate. The full144 B output remains unknown except for the two supplied mode bytes until later source writes reuse stack storage. Such later saved-register/private-record writes are new source definitions, not additional stat metadata. [SF1-SF5; SF-A3-SF-A5]

## Errno access and caller status channel

The error accessor returns the already-declared borrowed pointer E=`0x6600020000`; it adds no allocation or initial errno value. Its zero-visit continuation stops before `0x1006222d4`, a four-byte read of E, with all four bytes still undefined. Each errno-word continuation supplies only those four bytes. Both nonzero lstat controls cross errno values0,2,13 and`0xffffffff`. These are independent scalar controls, including synthetic combinations, not observations of native errno state. [SF1-SF4; SF-A4-SF-A5]

The original errno gate`0x1006222d4..0x1006222fc` selects index`0x28ef` exactly for errno2 and`0x28f2` for every other u32. The current SDK identifies2 as `ENOENT`. The original wrapper then stores a raw status through the reused caller record at R+8, where R=`0x6800070db8`. Source `0x10042f4cc` reads the adapter's private status cell; `0x10042f4d0` writes R+8. This is a record output, distinct from ordinary integer-return registers. [SF1-SF5; SF-A5]

| Source condition | Raw caller status32 | Subsequent retained request |
| --- | --- | --- |
| Link-type mode match | 0x74c29dd3 | malloc(64) |
| Nonzero lstat result, errno2 | 0x74c29dd1 | malloc(64) |
| Nonzero lstat result, other errno | 0x74c29dd3 | malloc(64) |

All these retained branches call `0x1007106f0 -> 0x100436378`, IA`0x58a3`, before the common imported malloc at`0x100710758`, IA`0x6aa4`, X0=64. The allocation remains pending. Its final payload type, result, ownership and later status handling are unknown here; a64 B allocation request alone does not establish an error-object layout or file descriptor. [SF1-SF4; SF-A4-SF-A8]

## Per-object synchronization and field uses

For the selected non-link mode, the source reads the SIDB object's raw lock pointer at object+0 through`0x1004cffd0`, builds a private record and calls`0x1004d0094 -> 0x10041a300`, IA`0xc270`. That adapter reaches the first once request. With the inherited SIDB object B=`0x6600006000`, its lock argument is L=`0x6600007000`. The request sequence below is source-paired. Native successful acquisition or release is unknown. [SF1-SF4; SF-A4,SF-A6-SF-A8]

| Source site | Imported interface | Relevant arguments / modifier |
| --- | --- | --- |
| 0x10041a59c | pthread_once | X0=0x1010b8cd0, X1=0x10040ebd4; IA0x8489 |
| 0x10008a9f4 | pthread_rwlock_rdlock | X0=L; IA0x57 |
| 0x1004292c8 | pthread_once | Same control and callback; IA0x8489 |
| 0x100082454 | pthread_rwlock_unlock | X0=L; IA0x5431 |
| 0x100d8fefc | ___error | Borrowed E returned by premise; IA0x6e96 |
| 0x100d8ff74 | open | X0=B+32, W1=0x110, u64 zero at[SP]; IA0x4a94 |

The acquisition return reaches source`0x1004d0098`, which reads the zero u64 at B+8. On this retained route the caller reloads L at`0x1004984fc`, calls`0x10049858c -> 0x10042904c`, IA`0xda9c`, and reaches the cleanup once/unlock pair. The zero-field route subsequently writes u32`0xffff5b81` to B+28 at`0x100514218`. This is the sole object-byte change in the complete lock-to-open chain. The field's full semantic type remains unknown; neither its prior zero nor this bit pattern is sufficient to assign a native descriptor/handle type. Other pathname objects and the SIDB pathname/undefined gaps remain unchanged. [SF1-SF4; SF-A2,SF-A7]

Once completion is modeled both without a new callback invocation and with the original callback executed separately from`0x10040ebd4`. The explicit invocation uses a256 B stack gap and a private return token, verifies its64 B frame/guard/return and preserves callee-saved registers and vector state. Its only image stores update controllers`0x1010c5088` and`0x1010c4670`; its one internal call targets the single-RET leaf`0x10044fc34`. It constructs no lock. The prior all-u64 controller-update equation is rebuilt, and every callback instruction is independently replayed for this new context. Native pthread stack placement and actual once scheduling remain unknown. [SF1-SF5; SF-A6]

The current SDK gives `sizeof(pthread_once_t)=16` and `sizeof(pthread_rwlock_t)=200`. Every modeled once return invalidates all16 control bytes; each read-lock/unlock return invalidates all200 L bytes. The retained source reads or writes neither the once-control bytes nor the opaque L bytes after these returns; the verifier checks that boundary explicitly. The first compile probe rejected an eight-byte once-extent assumption, which was corrected before evidence generation. Synchronization return controls0 and35 preserve the source PC sequences in paired cases. Value35 is a synthetic register perturbation for these interfaces; address agreement and source-path agreement do not prove native successful locking or the complete return domain. [SF1-SF6; SF-A3-SF-A4,SF-A6-SF-A7]

## Open record chain, flags and variadic argument

After the pre-open field write, source calls `0x100689800 -> 0x10043d044`, IA`0xa499`, then `0x10043d324 -> 0x100d3e6d8`, IA`0xc037`, and `0x100d3e940 -> 0x100d3d658`, IA`0x7dde`. These selected adapters carry the SIDB object through private records and reach the second errno accessor. Source`0x100d8ff00` writes u32 zero through E; it does not require an initial errno value. [SF1-SF4; SF-A4,SF-A7]

At`0x100d8ff50`, source reloads the SIDB object pointer from SP+80; `0x100d8ff54` computes its inline path at+32. Source`0x100d8ff68` writes an eight-byte zero at SP, and`0x100d8ff6c` supplies W1=`0x110`. The pending imported open has SP=`0x680005fe50`, X0=`0x6600006020` and W1=`0x110`. Its path is `/var/db/fpsd/SC Info/SC Info.sidb`, reconstructed in the parent source rather than introduced as a cleartext API fixture. [SF1-SF4; SF-A2,SF-A7]

| Open argument / flag | Established representation | Current SDK interpretation |
| --- | --- | --- |
| Path | X0=B+32 | const char pointer |
| Flags | W1=0x110 | O_RDONLY(0) OR O_SHLOCK(0x10) OR O_NOFOLLOW(0x100) |
| Supplied variadic zero | Eight zero bytes at[SP] | Darwin arm64e variadic argument placement, reproduced by the compile probe |
| X2 | Remaining declared volatile-register value | No semantic third-argument assignment |

The compile-only function `open(path,O_RDONLY|O_SHLOCK|O_NOFOLLOW,0)` emits `STR XZR,[SP]`, `MOV W1,#272`, and a call to `_open`, matching the source's stack/flag placement. Stored header hashes are SDK-relative and the recorded sysroot argument is portable. The probe verifies the current ABI; historical library implementation equivalence remains unknown. No create flag, descriptor return, file data, native file lock or kext traffic is established by the pending request. The per-object rwlock requests and the file-lock flag have distinct source roles. [SF1-SF6; SF-A3,SF-A8]

## Assumption register and falsification probes

| Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- |
| SF-A1: Pinned image and logical fixups apply | All source addresses, opcodes and bindings | Verify source SHA, each instruction/fixup and authenticated modifier; no hardware PAC inference. |
| SF-A2: Sixteen pending-lstat parents are conditional entries |32 contexts and128 pending opens | Exact GP/Q/NZCV/SP, owner and known-byte joins; preserve earlier native epoch uncertainty. |
| SF-A3: Current arm64e SDK describes modeled output/control extents |144 B stat,16 B once,200 B lock and flag/prototype terminology | Recompile assertions and variadic assembly; hash SDK-relative headers; historical runtime equivalence remains unknown. |
| SF-A4: Declared API returns and explicit opaque effects apply | Metadata/errno boundaries and synchronization continuations | Remove complete output spans, split private fixture fragments and clear private masks; never promote stale stack bytes; verify all return-state joins. |
| SF-A5: Supplied mode/errno words are separate scalar controls | Mode/link and missing-path partitions | Preserve unknown reads first; supply only2/4 B; prove all-u16/all-u32 predicates; mark positive lstat and unusual errno combinations synthetic. |
| SF-A6: Separate callback invocation uses a256 B gap | Original controller effects and following once return | Independently replay guard/return, saved GP/Q state, exact memory effects and source controller equation; native pthread scheduling/stack remains unknown. |
| SF-A7: Selected mode0x81a4 and B+8 zero route apply | Lock/unlock pairing, field+28 write and open chain | Cross both ABI patterns, callback choices and status0/35; verify path-sequence pairs, exact object masks, stack zero and unchanged other paths/generated32 B field. Nonzero B+8 remains unexplored. |
| SF-A8: Pending source requests do not establish native effects | Filesystem/environment/IPC limits | Retain exact pending open and malloc boundaries without descriptors/contents; require independent native epoch evidence for effects and daemon-kext pairing. |

## Reproducibility and bounded continuation

Checks logical SHA-256: `093f49d0085d6c94cbaf1a27b68a3a7e2d0caee8354eb0e5162dff7c048a9008`. Audit logical SHA-256: `3a216888a8eb8d2767efee8f24b12dbadffcc8a5c9636c71cba37f4f4ef49cce`. The extractor, auditor and verifier are linked above. Receipt JSON and the manifest use `zstd --ultra -22 -q -T1`; all analyst-local paths are excluded from the published files and decoded receipts. [SF1-SF6]

The32 contexts cross all16 parents with both new ABI patterns. Each has3 lstat-return intervals,6 mode intervals,2 opaque errno-accessor intervals,8 errno-word intervals,20 synchronization/open return intervals and2 callback intervals:41 per context,1312 total. The dataset contains96 lstat cases,192 mode controls,64 errno accessors,256 errno-word controls,128 open continuations and64 callback invocations. It retains281760 source visits,61536 reads,15296 writes,8224 logical edges and1024 internal calls. Independent replay checks9058304 scalar register values,9058304 vector register values,283072 flag states,382080 read B,110336 write B and6176 authenticated logical edges. It verifies800 API-return joins,448 supplied-output state joins and64 callback invocation joins. The128 open continuations verify1024 zero variadic-stack bytes and preserve4096 carried generated-stream bytes. [SF3-SF4,SF6]

Eight nonvacuous source equations cover all-u32 lstat dispatch, all-u16 link-type dispatch, all-u32 errno dispatch, all-status caller stores, all-pointer open-path construction, all-SP stack-zero/flag setup, all-pointer pre-open errno zeroing and the reused all-u64 callback-controller formula. Solver limit is30 s/query. Widths and arithmetic are exact u16/u32/u64; byte counts are exact for these conditional paths. The forked extractor is O(retained visits+effects+parent bytes) time/storage; independent replay is O(V*(register state+effects)+query DAG) time and O(receipts+largest interval+known byte map) storage. Counts are not native timing or heap measurements. [SF1-SF6]

| Impact | Next evidence | Architectural purpose and current boundary |
| --- | --- | --- |
| High | Open return partition, descriptor publication and fstat/read calls | Establish actual source descriptor/file-data contracts without assigning a type from the +28 bit pattern alone |
| High |64 B allocation result and status-envelope consumers | Recover what the common wrapper publishes for link-type/missing-path/other-error statuses |
| High | Native pathname, metadata and open event correlation | Establish environment-specific effects and any daemon-kext data transport; current source/ABI evidence is conditional |
| Medium | Nonzero B+8 route and later object fields | Recover alternate state handling and object lifecycle |
| Medium | Cleanup after open failure and full lock lifetime | Determine descriptor/object cleanup and native acquisition effects |
| Medium | Native once/control implementation and runtime SDK identity | Resolve scheduling, historical extents and library equivalence |

**QG1** passes: factual source/ABI analysis. **QG2** passes: SF-A1-SF-A8 register assumptions and probes. **QG3** passes for this metadata/synchronization/open increment; the full interface goal remains active. **QG4** passes: exact widths, extents, stack placement, counts and complexity. **QG5** passes: result versus errno, output versus stale backing, current SDK versus native runtime, per-object versus file-lock requests and supplied versus observed state remain distinct. **QG6** passes after independent replay, eight nonvacuous equations, compile/source/provenance checks and exact publication verification. **QG7** passes: bounded expansion covers descriptors/data, status envelopes, native environment/IPC linkage, alternate object state, cleanup and runtime identity.
