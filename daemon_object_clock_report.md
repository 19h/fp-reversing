# Object tail, clock calls, callback lookup and a separate cache

The conditional872-byte initialization path now reaches a full64-key value lookup through callback `0x1009D92D0`. This lookup reads **entry+8**, while the previously recovered removal path consumes the head at entry+10. It does not insert the new object into that table. The new path also establishes object tail fields, a second clock call, lock-adapter composition and a separate36-byte cache-allocation request. Native AEE caller, registry ownership, complete types and872-byte object publication remain **unknown**. The full daemon/kext/deeper-interface investigation remains active. [OC1-OC14]

Primary image: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. IDB target: `6b117c693e3b`. [Restored contexts](triage_evidence/daemon_object_clock_context.json), [contracts](triage_evidence/daemon_object_clock_contracts.json), [private continuations](triage_evidence/daemon_object_clock_profiles.json), [source proofs](triage_evidence/daemon_object_clock_proofs.json), [checks](triage_evidence/daemon_object_clock_checks.json), [preservation](triage_evidence/daemon_object_clock_preservation.json), and [scoped gates](triage_evidence/daemon_object_clock_quality_gates.json) retain reproducible evidence. The preceding [initialization report](daemon_object_initialization_report.md) remains frozen.

| Assumption | Dependent result | Stress test / falsification probe |
|---|---|---|
| OC1: The pinned image and original chained fixups define this specimen | All source addresses, slots, byte banks and bindings | Rehash original source and pointer words; compare848 fresh read-only IDB bytes |
| OC2: The three retained private initialization contexts apply | Continuation composition | Reconstruct all6,436,959 parent visits and1,512,380 memory effects; verify owner snapshots and saved general registers |
| OC3: Ordered source writes and pointer def-use restore the boundary | Private resumed state | Rebuild65/64/65 memory groups; retain per-register/spill pointer origins; no native continuity is inferred |
| OC4: Incoming frame mode471C and saved control word8B3DC651 select the retained clock branch | Two-call sequence | Prove the full u32 first gate; retain the alternate control-word target separately |
| OC5: Clock outputs/statuses and volatile-register values are declared ABI outcomes | Tail seconds and status sensitivity | Vary success/failure independently between the two calls,seconds0/reference/-1/above32 bits,upper result bits,NZCV and caller GPRs |
| OC6: Clock padding,errno/library effects and vector state are unavailable | Defined-read boundary | Invalidate4 timeval padding bytes; stop before undefined frame/heap or vector reads; no padding read occurs |
| OC7: New runtime words and lock-cell values are declared private inputs | Adapter and lazy-lock paths | Extend only unknown upper32 controller bits; vary auxiliary64-bit states and NULL/non-NULL lock cells; audit that newly supplied cells were unread in the parent prefix |
| OC8: The populated lock is a borrowed200-byte owner and pthread_once has already completed | Acquisition/callback/cleanup composition | Verify original once/lock/unlock arguments and slots; invalidate opaque16/200-byte API objects; callback invocation by the library is not modeled |
| OC9: Modeled lock operations return0 or22 with the declared scalar ABI effects | Bounded source execution after those returns | Preserve SP/X18-X29,clobber volatile GPRs/NZCV,and run all cases again; callback execution does not prove successful native acquisition or serialization |
| OC10: Registry fixtures are empty or two valid32-byte entries with the supplied keys/values | Finite lookup paths | Test empty,miss,first match,last match; prove full64 equality,stride,index increment and exhaustion; native table publisher remains unknown |
| OC11: Generic scan premises include stable count N:u32,nonnull table and an owner of at least32*N bytes | Compact scan semantics | Initial index0 advances by1 until equality with N; i<N implies address arithmetic fits u64; native concurrency and ownership remain unknown |
| OC12: Global cache cell1010C6840 is NULL in the matching fixtures | Cold36-byte cache frontier | Prove the all-u64 NULL/non-NULL selector and source allocation/publication contract; warm-cache contents and native initial value remain unknown |
| OC13: Logical pointer authentication is the validation boundary | Callback and import identity | Check IA key,original modifier,ad=0 and register-specific origins through STP/LDP; no hardware PAC executes |
| OC14: Finite software execution and source-local proofs have distinct coverage | Interpretation and completion | Recompute all96 continuations; preserve the two genuine external/runtime frontiers and keep native transport/object publication unresolved |

Whole-prefix claims depend on OC1-OC10 and OC13-OC14. Generic scan semantics additionally require OC11. The cache branch uses OC12. Scalars introduced by private fixtures retain their origins; no internal phase,branch target or continuation is replaced.

The parent journals contain source-produced frame/memory state and final general registers, but do not record pre-call NZCV or vector registers. Restoration reconstructs only the available state. The modeled clock return supplies fresh declared NZCV before any continuation instruction executes. Source in the retained parent contexts uses no vector registers. The new executor rejects vector reads and undefined private reads. Paired stack spills/reloads carry pointer origins, resolving the callback through its actual saved slot instead of treating a provenance limitation as a PAC failure.

The initial IDA request failed because its authenticated bridge was unavailable. Subsequent reads succeeded; [retry bytes](triage_evidence/daemon_object_clock_ida_retry.json) and [additional bytes](triage_evidence/daemon_object_clock_ida_more.json) cover seven ranges/848 bytes and match the image. Their tool output uses tabular text; the recovery script parses explicit addresses and byte extents. No IDB mutation occurs.

| Source site | Boundary or effect | Evidence scope |
|---|---|---|
| BAD4C8 | First gettimeofday(F+3CA0,NULL) | Original slot10109FF20,IA/9298/ad=0 |
| BAD4D8..BAD504 | Saved SP+2AB8 control-word gate | All-u32 source proof; actual retained word8B3DC651 |
| 87CBE0 | Second gettimeofday at the same output address | Executed under declared ABI outcomes |
| 87CBEC..87CC08 | Test W0 of the second call | All-int32 success/failure partition; upper X0 bits have no role in this test |
| D2FA48 | Successful second-call result | Load only low32 timeval seconds |
| 9B2A68 | O+354:u32 | low32 seconds on success;0 on any nonzero second status |
| 9B2A6C | O+358:u64 | Opaque incoming u64 G |
| 9B2A70 | O+360:u64 | NULL link |
| 9B2A80 | SP+3620:u64 cursor | Subtract656; retained704 becomes48 |

For the retained first-call phase, the control gate chooses indexC1C8 when SP+2AB8 equals8B3DC651,otherwiseB31E. There are40 source visits between the two clock calls. Their register read/write sets show that the first result in X0 is overwritten before use; their ordered reads do not access its timeval output before the second call writes that buffer. This is conditional on the recovered control-word branch; it is not a claim about every caller.

The second-call gate selects index5379 ->D2FA40 on W0==0 and5357 ->9B2A54 otherwise. Both slots use IA/55DB/ad=0. Success loads W9 from the seconds address; failure keeps W9=0. Microseconds and padding are not consumed through the checked continuation. The installed arm64e SDK compile freshly verifies timeval16 bytes,sec64 at+0,usec32 at+8,and the imported signature. The installed build ABI is distinct from the daemon's unknown build SDK. The failure fixtures explicitly supply output bytes; they do not assert that a native failing gettimeofday leaves or writes those values.

Distinct incoming data flows are preserved:

```text
incoming SP+2A70 -> source SP+2B50 -> X20 at9D91BC -> object+358 (G:u64)
incoming SP+2A60 -> source SP+3588 -> full64 query Q -> table.key+0
                                                           |
                                                    table.value+8
                                                           |
                                                       SP+2AE8

incoming SP+2A50 -> saved raw H -> object+CC
                      |
               D=H XOR8B3DC651 -> input copy of D bytes to object+4
```

The length/copy flow is established in the preceding increment. G and Q are separate u64 inputs. In particular,the original SP+2A70 input is saved before that frame slot is reused for phases and function pointers. The later value G=123456789ABCDEF0 in these fixtures is a declared input,not a recovered native identifier. Source9B2A6C stores all64 bits unchanged. The u32 seconds store at+354 and NULL link at+360 are adjacent but have different roles and widths. Matching a destruction-field offset still does not establish a complete native class or shared allocation lifetime.

For saved mode471C,the lazy gate uses W22=07F4 and loads callback9D92D0 through slot10103DE90,IA/56F7. W20 becomes40C7 in this **different epoch**; it is not the gate's callback-table index. This extends the earlier callback evidence without changing it:

| Retained operation | Actual gate W22 | Callback target | Source evidence |
|---|---|---|---|
| Removal | 0817 | B353A4 | Previous retained removal journals |
| Initial reset candidate | 07E9 | B280C8 | Previous conditional zero-marker route |
| Post-clock lookup | 07F4 | 9D92D0 | New continuations |

Lock NULL selects the known creator and reaches `_malloc(200)` at19385C before execution. Lock non-NULL selects the known acquisition adapter43E280; declared completed-once and primitive outcomes allow source to return through the shared C02F3C trampoline and invoke9D92D0. The return path retains the actual callback pointer through paired stack stores/reloads.

| Import request | Source site | Original slot / IA modifier | Meaningful arguments |
|---|---|---|---|
| pthread_once | 43E508,442650 | 10109FE80 /8489 | control1010B8CD0,callback40EBD4 |
| pthread_rwlock_wrlock | 361DF4 | 1010A0A00 /4C4D | Declared borrowed lock pointer |
| pthread_rwlock_unlock | 208EFC | 1010A0D78 /5431 | Same borrowed lock pointer |

The once control and lock objects are opaque16/200-byte owners under the retained SDK ABI. Source does not read their modeled implementation bytes. The tested nonzero primitive returns still proceed through the observed source path; these cases establish control-flow sensitivity,not native lock ownership or a concurrent failure scenario.

Callback9D92D0 distinguishes Q==`0xE3B88695C0D52DBC` from other u64 queries. The special branch9E41F0 loads the first table entry's+8 value; its native pointer/count prerequisites are unknown and this branch is not executed here. The ordinary branch uses global count1010CA2B0 and table pointer1010C9288.

At963CB4,SP+2A68 is reused for the index-output address F+344C; it no longer denotes the allocation pointer saved there in the earlier epoch. SP+2A70 is also reused for a continuation pointer. The object remains separately saved at SP+2C08. These frame epochs are tracked independently.

For a stable nonempty table with N entries,the ordinary scan compares full64 entry.key with Q,using32-byte stride. Source839160 increments the u64 index and839164..839188 implements an equality-based exhaustion test. It selects AB17 for another iteration and AB3F when the incremented index equals N. Under N:u32 and initial index0,this visits at most N entries;32*N fits u64. The first match stores its u32 index at the supplied index-output address. Native bounds/owner validity remain premises.

| Table entry / output | Width | Source use |
|---|---|---|
| Entry+0 | 8 bytes | Exact full64 query comparison |
| Entry+8 | 8 bytes | Value loaded at8F2444 after an index match |
| Entry+10 | 8 bytes | Earlier head/removal interface; untouched here |
| Frame+344C | 4 bytes | Search index,-1 before scanning,0/1 in the finite matches |
| Frame+2AE8 | 8 bytes | Returned value,0 for the tested empty/missing cases |
| Frame+3508 | 4 bytes | 8B3DC651 for tested matches;74C29F00 for tested empty/missing cases |

All table fixtures contain either zero entries or two explicit32-byte entries. The finite keys exercise first and last matches and a miss; returned values44440000/44440001 are declared scalars. Neither a pointer type nor a native identifier meaning is assigned to them. No table entry is written in these continuations. The pointer at entry+10 and the object link at+360 are not connected by a publication store in this increment.

The creator/acquire/cleanup adapters use u64 state at C4670,C5040,B66A8 andB6738. C4E18 is read as u32 in these paths; its supplied upper32 fixture bits are unused and establish no native64-bit field layout. Newly required upper32 bits at C4670 and the auxiliary words are declared inputs. The newly supplied auxiliary/cache/registry cells were not read in the parent prefixes. Source-local formulas are proved for all64-bit inputs. With C=`73D046208EAED1A6`,callee SP=S,multiplier K and preceding scalar t:

```text
creator: z = ((t + S + 8 + B) XOR C) * K
         state[C5040] = state[C4670] = z

acquire: u = t + S + 8 + B
         state[B66A8] = (u*K) XOR C
         state[C4670] = (u XOR C)*K

cleanup: z = ((t - S - 8 + B) XOR C) * K
         state[B6738] = state[C4670] = z
```

These are u64 modular formulas. Their address/state-derived obfuscation role is established locally; native synchronization of the state words is unknown. They are not Mach port names or transport descriptors.

After cleanup,the matching paths perform further scalar sampling using the existing PRNG state and the previously recovered nonzero byte leaf. The finite checks cover128 full624-word twists/79,872 exact u32 updates,and432 accepted bytes with8 zero retries across the24 matching paths. The accepted bytes occupy two separate scratch regions per path; no combined native structure or security property is inferred. Empty/missing paths instead reach a new u64 runtime-state read atB6CC0 in the timestamp-dependent continuation ABD698; its native value and decoded comparison remain unknown.

The matching paths reach a different global cell,**1010C6840**,saved from incoming X10 at AEE5D4 through SP+21D0. Under the declared NULL value,A42D8C..A42DAC selects9C00E0 and then requests `_malloc(36)` at9C0148. An exhaustive256-input byte bank resolves original malloc slot10109FF58/IA6AA4. The continuations stop before this allocation.

The subsequent source-local contract9C014C..9C0158 stores the full malloc return into cell1010C6840 before testing it for NULL. This is proved for all u64 returns,including0. It is a **separate cache pointer publication**,not publication of the872-byte object,and is not executed by the96 continuations. Warm-cache contents,later36-byte initialization and caller-visible results remain unknown.

Validation covers25 named source spans,2,488 original opcodes,101 original fixups,one exhaustive bank,25 proof pairs/50 UNSAT files and178 lifted source instructions. All96 private cases/1,843,436 new source visits are freshly recomputed. The independent byte ledger checks348,224 reads and89,296 writes,192 clock models,192 opaque synchronization models,288 tail stores and the finite PRNG/sampler effects. Seven fresh IDB ranges match848 bytes. Parent reconstruction,source equations,finite byte/state checks and repeated A64 execution are separate evidence layers. Native daemon,allocator,clock,locking,IPC and hardware PAC are not executed.

Reproduce with the preceding increment's pinned Python/Z3 environment,running `capture_daemon_object_clock.py`, `probe_daemon_object_clock.py`, `recover_daemon_object_clock.py`, `prove_daemon_object_clock.py` and `validate_daemon_object_clock.py` from triage_evidence via Python's `-P` option and the documented PYTHONPATH. The generic scan is O(N) time/O(1) auxiliary state under OC11; evidence reconstruction/replay is O(source visits+effects+solver resources) time/O(largest journal) space. Each solver query has a30 s limit. Frame/field offsets are hexadecimal; extents are bytes. Clock seconds are signed64 API values,but the object store copies only their low32 bits.

| Impact | Further interface question | Discriminating evidence |
|---|---|---|
| High | Where is the872-byte object actually published or retired? | Continuous pointer provenance beyond the cache/timestamp frontiers into registry stores or frees |
| High | Who supplies G,Q and the actual AEE frame? | Native/source callers,including saved-frame epoch ownership and continuation49D production |
| High | What are the36-byte cache contents and1010C6840 lifetime? | Original successful allocation continuation and warm-cache readers |
| High | What does entry+8 mean,versus the head at+10? | Independent writers,native record creation and consumers beyond SP+2AE8 |
| Medium | What does the u64 state atB6CC0 encode? | Its writers and the complete timestamp-comparison codec |
| Medium | How do lock/state-word updates behave with native interleaving? | Actual ownership,once initialization and source writer census; current models are serial |
| Medium | Where is the saved main-port value consumed? | Data dependence from SP+2A18 into a resolved IOKit/Mach call and its emission PC |

QG1 passes for factual source/ABI analysis. QG2 is covered by OC1-OC14. QG3 passes for this increment; the full objective remains active. QG4 covers widths,modular arithmetic,byte extents,loop bounds,clock units and complexity. QG5 separates value lookup from head insertion,cache publication from object publication,private API outcomes from native effects,and static contracts from executed coverage. QG6 uses original bytes/fixups,rebuilt contexts,source proofs,byte/state ledgers,recomputed continuations,SDK compilation and fresh IDB bytes. QG7 retains the bounded leads above. Machine-readable gates are emitted after semantic and preservation checks pass.
