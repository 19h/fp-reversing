# FPSD1200 pool initialization, publication and application-word continuations

The original FPSD1200 continuation requests 44800 bytes, initializes three metadata fields in each of 50 slots at a stride of 896 bytes, publishes the allocation pointer and slot count into process-local globals, and changes the first slot's marker. The following source branch distinguishes the sampled application words: 1 and 2 reach a process-local atomic operation and then an `arc4random` boundary under an explicit atomic fixture; 3 and reference word `0x11223344` return application status zero through the original wrapper. Those returns still carry fixture seeds in reply outputs. They establish neither valid output objects nor a successful daemon-kext transaction. [FA1-FA8]

This continues the [PID/FPDI identity report](fpsd1200_identity_report.md) from its allocation boundary. All preceding original admission, token, identity and initialization code remains continuous. The report completes one bounded increment; the full multi-level investigation remains active.

## Assumption register

| ID | Assumption / dependent results | Stress test / falsification probe |
| --- | --- | --- |
| FA1 | The pinned thin daemon and selected live IDA bytes identify the inspected source. Every recovered address and instruction role depends on this identity. | Rehash the original slice, all 106 source spans, 242 format12 rebases and 28 bind/import records. Input-file metadata and selected-byte agreement remain distinct. |
| FA2 | The prior selected libbsm body, Security/CF results and retained provider buffer implement the declared private environment. Entry into this continuation depends on those premises. | Recheck the exact cache/export body, original API events, token copies and buffer reads. Native entitlement results and runtime library pairing remain unknown. |
| FA3 | Private mappings, normalized logical pointers, skipped PAC and stack-probe/once/lock models delimit execution. All finite continuations depend on this machine. | Independently replay every original visit, import, GP/SP/NZCV checkpoint, original callback return and terminal stack, private and heap state. Native authentication, pthread state and concurrency require separate evidence. |
| FA4 | `malloc(44800)` returns the declared disjoint private owner or NULL; backing fill is diagnostic and does not define target allocation bytes. Pool layout and initialization conclusions depend on that allocation contract. | Compare A5 and 3C backing fills, track each source write byte, check all owner/tail bytes and retain a stop-before-write NULL control. Existing nonnull pool reuse and native allocator behavior remain untested. |
| FA5 | The request words and OOL counts are scalar fixtures. Application-word observations do not assign a method name or certificate meaning. | Independently vary request+52 across 1, 2, 3 and `0x11223344`, with matching counts 8 or 756 at +40/+60. Verify no OOL byte is read; a count756 fixture is not a reconstructed certificate. |
| FA6 | Optional `CASAL` handling models scalar single-thread compare/store semantics only. The continuation beyond that instruction depends on this additional fixture. | Retain matched pre-atomic stops, compare all 31 GP registers/SP/NZCV and old/expected/desired words, replay the original reset, then stop before the random API. Native acquire/release ordering and contention are unknown. |
| FA7 | Reply seed bytes and numerical task-local port names are not established output objects or rights. Status/formatter observations depend on preserving that distinction. | Monitor the inline128-byte region and payload output cells throughout the protected call, compare before/final bytes and check the outer status carrier separately from descriptor bytes. Recover actual output producers and native receive/send records independently. |
| FA8 | Finite profiles and local arithmetic certificates bound this result. Source-fragment roles are not complete C prototypes or whole-program semantics. | Rerun the independent audit, three local UNSAT queries and all 4352 bank inputs; retain 384 unpaired lookup observations. Establish other slot indices, existing-pool states and later provider/IOKit calls separately. |

## Primary provenance [FA1-FA3,FA8]

| Object | Identity / coverage |
| --- | --- |
| Original daemon arm64e slice | SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; preferred base `0x100000000` |
| Read-only live IDA | Input metadata SHA-256 `4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7`; all 106 selected code-span hashes match the thin slice. The differing file hashes are retained. |
| Source catalog | 8116 unique daemon instructions / 32464 bytes, including two pre-execution guard sites; the atomic instruction is modeled in other profiles. Contiguous spans do not define C-function boundaries. |
| Selected libbsm | The [prior identity provenance](fpsd1200_identity_report.md) is retained and rechecked: current cache/library UUIDs and exact `_audit_token_to_au32` body SHA-256 `76ed6c9a5a2b1b51e22d1fd36ca9802e734187970d71868438eb981b52e613e5` |
| Pointer/bank evidence | 242 rebases, 28 bind/import records, 17 exhaustive adjacent-bank identities and 2959 observed pair uses; 384 unpaired reads remain observations |

Evidence: [source, profiles and certificates](triage_evidence/fpsd1200_arena_checks.json.zst), [fresh IDA attestation](triage_evidence/fpsd1200_arena_ida_readback.json.zst), [producer](triage_evidence/recover_fpsd1200_arena.py), [independent replay/oracles](triage_evidence/audit_fpsd1200_arena.py), [exact publication audit](triage_evidence/verify_fpsd1200_arena_publication.py). The operation-specific IDA knowledge-store search returned no matching fact. No IDB mutation or native target execution occurred.

## Allocation, slot metadata and publication [FA3,FA4,FA8]

| Original site | Established effect in every nonnull-allocation profile |
| --- | --- |
| `0x100419178` | Imported `malloc`, X0=`0xaf00`=44800 bytes; modeled result is a disjoint private owner |
| `0x10013ebe0` | For slot i=0..49, store u32 `0x4577df49` at allocation+i*896+876 |
| `0x10013ebe4` | Store u64 zero at allocation+i*896+880 |
| `0x1001b4724` | Store u64 zero at allocation+i*896+888 |
| `0x100057630` | Imported `free(NULL)` in the fresh-pool fixture; record-only, with no native deallocation |
| `0x100057634` | `STP X20,X22,[X25]` publishes the pointer at `0x1010c4cd8` and u64 count50 at `0x1010c4ce0` |
| `0x10051e04c..0x10051e050` | Computes selected index*1024-index*128 = index*896, using 64-bit modular arithmetic |
| `0x10051e068` | Selected index0: overwrite the u32 field at slot+876 with `0x4577df4a` |
| `0x100442650` / `0x100208efc` | Revisit the once adapter, then unlock the same modeled rwlock at `0x1010b7478`; the once fixture invokes no second callback |

The original initialization makes 150 metadata stores, defining exactly 50*(4+8+8)=1000 unique bytes. The later marker overwrite adds one event without increasing that byte set. The requested owner extent is exactly 50*896=44800 bytes. Consequently 43800 allocation bytes remain untouched by this prefix. These are exact byte counts, not inferred native structure sizes. The 64 KiB private backing is only harness capacity; its 20736-byte tail is also checked unchanged.

No source heap read occurs in any of the 12 profiles. Changing the diagnostic owner fill from A5 to 3C leaves the original instruction sequence, import events, CPU checkpoints, reply bytes and terminal stack/private state identical. This supports the recorded write-only initialization prefix; it does not establish definedness for later slot consumers. The marker meanings, remaining slot fields, ownership lifetime, expansion/reuse policy and session/client association are unknown.

```text
44800-byte private owner
  slot[0]  base+0*896
  slot[1]  base+1*896
  ...
  slot[49] base+49*896

each 896-byte slot:
  +0 .. +875   no source store in this prefix
  +876 .. +879 u32 0x4577df49; selected slot0 becomes 0x4577df4a
  +880 .. +887 u64 0
  +888 .. +895 u64 0

initialize -> free(NULL) fixture -> publish pointer/count -> mark slot0 -> unlock
```

The NULL allocation control stops before original `STRB W17,[X20,X21]` at `0x100052440`, with X20=0 and X21=`0xaeff`. The computed byte address is `0xaeff`, not zero. It performs no heap write and publishes no pool. This records a branch under a modeled allocation failure and incomplete private environment; native reachability, mapping and failure behavior are unknown.

## External application word and process-local atomic boundary [FA3,FA5,FA6]

At `0x100635670..0x1006356a8`, the original source masks W23 with `0xfffffffe`, compares against W9, computes a table selector and branches. In these profiles W9 at the comparison is `0x72d85fd8`. Words1 and2 produce W23=`0x72d85fd8` and `0x72d85fd9`, selecting `0x10037aa78`; word3 produces `0x72d85fda` and reference word `0x11223344` produces `0x83fa931b`, selecting `0x10057cfec`. This is a source-backed local selector with finite input correspondence; a complete application-word decoder is not established.

| Request+52 / controlled count | Retained endpoint | Original visits per profile |
| --- | --- | --- |
| Reference `0x11223344`, count8 with A5 and 3C allocation fills | Return through original wrapper/stub | 18677 each |
| Reference `0x11223344`, count756 | Same original return path | 18677 |
| Word3, count8 and count756 | Same original return path | 18677 each |
| Word1 or word2, count756, atomic fixture disabled | Stop before `CASAL` at `0x1006009c0` | 19177 each |
| Word1 or word2, count8 or count756, scalar atomic fixture enabled | Stop before imported `arc4random` at callsite `0x100630448` | 19229 each |
| NULL allocation, reference word/count | Stop before the guarded byte write | 7023 |

Varying the count independently preserves each sampled application word's instruction sequence and endpoint. Request+56 remains2. No OOL payload byte is consumed. These observations do not identify the application words as operation enums, prove certificate acceptance or generalize across arbitrary native state.

The original `CASAL W8,W14,[X12]` has X12=`0x1010b5de0`, old word=`0x5d96`, expected W8=`0x5d96` and desired W14=`0xa94ef`. The explicit scalar fixture stores the desired word and returns the old value in W8, preserving all other GP registers, SP and flags. No native atomic instruction or synchronization executes. An original later `STR W15,[X12]` at `0x1006303ec` restores `0x5d96`, so the transient update is not the terminal global value. All four modeled continuations then reach `arc4random` and stop before its implementation or result. The field's high-level synchronization role, contention path and random-value consumer are unknown.

## Original returns, reply definedness and Mach interfaces [FA3,FA7]

Five non-atomic-route profiles return through the original protected core and adapter. Carrier+24 is `0x8b3dc651`; the original outer XOR decodes application status zero. The adapter's computed stack delta is zero. The original stub constructs a 212-byte complex reply, descriptor count2 and ID1300. No protected-output replacement is used in these cases.

That local status is insufficient to establish useful reply outputs. Monitoring from the protected adapter entry through its return finds zero stores to the 128-byte inline output or the payload's output fields at +72..103. The inline bytes, OOL output-address cell, returned port-name cell and several scalar outputs retain fixture seeds; the prezeroed OOL count remains zero. Original wrapper copy-back propagates those cells. This agrees with the [earlier definedness boundary](fpsd1200_contract_report.md), now tested on an original zero-status return. It is not evidence of a native uninitialized-output disclosure, valid returned right or successful client parsing.

| Interface / original site | Established location and limit |
| --- | --- |
| Incoming application port argument, `0x10000467c` | Received local header name at request+12 becomes payload+0; numerical fixture name `0x1400`, with no new native object identity |
| Reply destination, original MIG header preparation | Retains the earlier request-remote/reply-destination contract; sampled reply remote name is `0x6400`, reply local name0 |
| Port-name copy-back, wrapper `0x100007f34..0x100007f60` | Writes the staged output name to reply+44; the value remains A5 seed bytes in these returns, with no new producer or right allocation |
| Reply descriptor constants / formatting, `0x100004628..0x10000462c` and `0x1000046f0..0x100004704` | Outgoing disposition19/type0 and complex reply structure are serialization evidence; these sites do not emit a message |
| Input retirement, `0x10000468c` | Original `mig_deallocate(input_OOL_address,input_count)` call after return; record-only fixture. Following original code clears the request address/count. |
| New emission sites | None established: no `mach_msg` send, successful port/OOL producer or IOKit call is reached in these prefixes |

The u32 at reply+32 lies inside the complex reply's OOL address descriptor. It is not the application-status word used by the separate 36-byte error format. The evidence reports the carrier-derived status and complex reply size separately; no offset32 status interpretation is applied to these replies.

## Verification and quality gates

The independent auditor never imports this increment's producer. It replays every retained original instruction and API event through the frozen loader/identity oracle, checks new heap reads/writes and byte-definedness, exact allocation contents/tail, pool publication, atomic boundary/effects/reset, new CPU checkpoints and protected output regions. The sole new atomic instruction is explicitly modeled in both implementations and is not counted as hardware validation. The producer replaces an inherited instrumentation counter with a declared global visit cap without resetting target CPU/memory.

| Independent check | Coverage |
| --- | --- |
| Finite profiles / replies | 12 / five zero-status complex reply returns |
| Original instruction visits | 215678: 215450 daemon and 228 selected libbsm |
| Imported events / original token copies | 378 / 120 complete 32-byte copies |
| Admission / new pool CPU checkpoints | 224 / 1196 GP/SP/NZCV checkpoints; prior identity checkpoints are also replayed |
| Original once callbacks | 12, one per profile; modeled invocation and return checks |
| Heap stores / loads / protected-output stores | 1661 / 0 / 0 |
| Terminal stack, private and heap comparison | 7864320 bytes across repeated private extents |
| Local UNSAT certificates | Three: modular slot-stride identity, metadata-field owner bounds and recorded outer-zero status |

The bank identities cover 4352 possible byte inputs. The source/finite checks do not prove full bank pairing, all slot states or whole-program correctness. Source/replay complexity is O(C(B+F+K)+R+256N) time, O(B+F+C*K+R) retained space and O(B+F+R) transient replay space, for cases C, image bytes B, fixups F, bounded visits K, retained evidence R and bank identities N. Solver cost is separate, capped at 15 s/query. Byte counts and 32-/64-bit modular widths are exact; no native timing or statistical inference is made.

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" "$PYTHON" -P triage_evidence/recover_fpsd1200_arena.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" "$PYTHON" -P triage_evidence/audit_fpsd1200_arena.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" "$PYTHON" -P triage_evidence/verify_fpsd1200_arena_publication.py
```

Generation reuses the retained read-only IDA attestation; a fresh live read is a separate operation. Nontrivial JSON uses zstd ultra22 archives with verified round trips. The publication audit checks exact ownership/manifest changes, three preserved original inputs and analyst-path scrubbing.

| Gate | Scoped result |
| --- | --- |
| **QG1** | Pass: factual interface/control/data analysis. |
| **QG2** | Pass: FA1-FA8 state assumptions, dependent results and falsification probes. |
| **QG3** | Pass for this increment: original allocation/layout/publication, sampled application-word control, atomic boundary, zero-status return and reply/Mach limits are covered. Full goal incomplete. |
| **QG4** | Pass: byte extents, source offsets, modular widths and terminal states reproduce. |
| **QG5** | Pass within scope: allocation NULL, undefined owner bytes, pre-atomic guards, scalar atomic effects/reset and reply seed propagation remain explicit. |
| **QG6** | Pass: original slice/fixups, matching fresh IDA code hashes, exact library body, independent replay and publication audit support the bounded claims. |
| **QG7** | Pass: impact-ranked continuations preserve unresolved native and cross-layer questions. |

| Impact | Further discriminating evidence |
| --- | --- |
| High | Continue the original word1/2 branch from `arc4random`, with declared result controls, and recover actual payload reads, output writers and provider/IOKit/Mach arguments. |
| High | Trace consumers of the published pointer/count and slot markers; establish complete slot identity/lifetime and existing-pool behavior before assigning a session registry or client ownership model. |
| High | Join actual native audit/Security context, process-local initialization, matched requests/replies and rights to the existing kext dispatch evidence. Local zero status and shared globals do not establish the daemon-kext interaction. |
| Medium | Recover the full application-word encoding, nonmatching atomic path, native synchronization and allocation-failure behavior, keeping missing environment distinct from target faults. |
| Medium | Recover capability elements, later identity validation and all output initializedness/cleanup paths; extend the earlier FPDI conclusions without equating local matching results with authorization. |
| Low | Compare pool markers/layout with other independently pinned operation carriers; shared fragment addresses alone do not establish shared business semantics. |

This is one completed investigation increment. The full interface goal remains active.

## Environment and certificate continuation

The [context continuation](fpsd1200_context_report.md) resolves the first random-result consumer, 624-word seed recurrence, clock/random material, readiness/arena/self-text dependencies, OOL certificate consumption and original error rollback. Nineteen independent profiles cover 7245815 original visits; the retained 756-byte DER reaches a later atomic gate, and an explicit scalar continuation reaches the root-CA allocation boundary. These cases extend the earlier prefix without changing its twelve-case scope. Native port/right producers, IOKit linkage and successful completion remain unknown (FX1-FX8).
