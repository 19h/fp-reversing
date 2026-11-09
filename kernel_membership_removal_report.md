# Static kernel membership removal and right-lifetime contracts

The CF source1 extraction request now has a source-pinned static mapping through
both libkernel routes to the same kernel extraction core. The fast route uses
Mach selector -23. On the selected fallback status, libkernel uses RPC 3227;
the matching kernel subsystem record selects a stub that calls the same core.
The core resolves a receive-right/port-set pair, unlinks membership, unlocks the
objects and frees a returned link. Right deallocation and mod_refs use different
dispatch paths and have different sentinel-name continuations.

This increment adds static instruction, binding, ABI and algebra evidence. It
adds zero target instruction executions, zero emulated instruction visits and
zero runtime-state observations. Native membership changes, right retirement,
caller authorization, concurrency and successful FairPlay processing remain
unknown. The broader interface goal remains active.

## Primary evidence and reproduction

Evidence consists of [original bounded functions and table/fixup records](triage_evidence/kernel_membership_removal_source.json),
[static assertions, call edges and solver queries](triage_evidence/kernel_membership_removal_contracts.json),
[fresh checks and SDK compilation](triage_evidence/kernel_membership_removal_checks.json),
[preservation seal](triage_evidence/kernel_membership_removal_delivery.json) and
[quality gates](triage_evidence/kernel_membership_removal_quality_gates.json).
The [extractor](triage_evidence/recover_kernel_membership_removal.py) reads original
files; the [analyzer](triage_evidence/analyze_kernel_membership_removal.py)
checks exact instructions and runs two finite-width algebra queries. No new IDA
query or database mutation was needed. All addresses are image virtual addresses
from the pinned files; runtime slides and loaded-image identity are unobserved.

Kernel collection SHA-256 is
`d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`,
kernel UUID `9b65bd6e-027b-34d1-a22b-ac03dccffc84`. Cache UUID is
`2bd06591-e751-3e84-963f-b08dab6af23a`; libkernel UUID is
`f2bceb9a-0fec-3c92-b6ea-8e37157050a8`; CF UUID is
`7fe5392e-ff16-31e1-8552-3a45c6b68224`.
The capture contains 14 complete kernel routines/703 instructions and ten cache
routines/498 instructions: 4804 function bytes, plus a separately captured
16-byte CF import stub and original metadata/constants. Five cache files are
hashed. Compiler bounds and original pointer chains are retained; anonymous
kernel routines are assigned inferred roles, not fabricated recovered symbols.

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_membership_removal.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/analyze_kernel_membership_removal.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_membership_removal.py
```

## Assumption register

| ID | Assumption / dependent result | Stress or falsification probe |
| --- | --- | --- |
| KR1 | The pinned kernel collection and cache are the selected static corpus. | Fresh function-byte/file hashes, original trap chains and subsystem record. Actual loaded-image pairing and native epochs remain unknown. |
| KR2 | Compiler function bounds and disassembly identify the captured instruction sequences. | Re-extract every function, verify length/hash and 68 exact instruction assertions; retain unresolved direct/indirect callees rather than claiming a closed graph. |
| KR3 | Original trap/subsystem names and exports establish operation identity; unnamed internal roles follow caller/data flow. | Check format8 trap/munger/subsystem chains, exact libkernel nlist/exports and CF import. Hardware PAC validity is not established. |
| KR4 | Installed SDK names/types and retained user/kernel message-layout evidence provide nomenclature for the captured widths/constants. | Compile selected layouts, compare source size guards and user/kernel offsets, retain SDK hashes. This does not identify an exact open-source kernel revision or attest a live transfer. |
| KR5 | Selected ordinary continuations are interpreted subject to valid lookup/lock/conversion inputs and returning lower diagnostics. | Identify every external callee frontier and return constant; keep conversion/diagnostic effects, permissions, lifecycle and native success unknown. |
| KR6 | The algebra models the matched u32 carry/zero and fixed LDR-W/STR-X sequences. | Original instruction assertions and two negated-equivalence UNSAT queries; altered widths/queries are rejected. No target-memory validity or execution-path proof follows. |
| KR7 | Shared allocator-class address and ring manipulation support the link-storage role inference. | Match allocation/free class construction and unlink return flow. Native allocator type, reference counts, race behavior and complete callee effects remain unresolved. |
| KR8 | Earlier status4/5 membership fixtures were supplied diagnostics. | Separate them from source-local return values and SDK meanings; add no native occurrence claim. Full daemon/kext/interface completion remains false. |

## CF, fast trap and fallback convergence

Use T for the task endpoint name, N for the member receive name and P for the
port-set name. All three are u32 task-local names, not CF references or kernel
pointers. CF's task argument comes through the original cached binding to
`_mach_task_self_`; the runtime value of that cell is unknown here. The service
name N and set P occupy separate arguments. A fallback RPC's remote endpoint
is T, not N.

```text
CF RemoveSource -> libkernel extract_member(T,N,P)
  fast -23 -> task-name conversion -> space -> extraction core
    if conversion returns null: status 0x10000003 back to libkernel
  selected fallback -> RPC 3227 -> kernel MIG stub -> space conversion
                                                 -> same extraction core
core -> pair lookup/type admission -> membership unlink
     -> object unlocks -> returned link free -> status continuation
```

| Binding / original location | Established static relationship |
| --- | --- |
| CF call `0x184779348` | Calls extract_member through original stub `0x188085b70` |
| Stub chained cell `0x1e2103ab8` | Resolves to exact libkernel export `0x18054b360` |
| Task-self import cell `0x1e01c8b30` | Resolves to `0x1ed83e960`, exact `_mach_task_self_` symbol; cell contents are not a live-name observation |
| Library fast call `0x18054b380` | Calls trap stub `0x180547b04`; static SVC at `0x180547b08`, X16=-23 |
| Mach table index 23 / cell `0xfffffe0007efb240` | Three-argument handler target `0xfffffe000bcdbd34` |
| Handler tail `0xfffffe000bcdbda0` | Calls core `0xfffffe000bcdffd8` with space,N,P |
| Library fallback `0x18056dcb0` / call `0x18056dd24` | Builds RPC 3227 and calls mach_msg2_internal |
| Subsystem `0xfffffe0007e67b08` | Original range[3200,3243); routine index 27 is request 3227 |
| Routine record `0xfffffe0007e67e88` / pointer `0xfffffe0007e67e90` | Resolves to kernel MIG stub `0xfffffe000bd87b68` |
| MIG stub call `0xfffffe000bd87bb0` | Calls the same core `0xfffffe000bcdffd8` |

The ordinary fast name-lookup route compares the resolved task candidate with
the candidate derived through the current-thread path and returns null when
they differ. Other branches of that conversion routine are retained but not
fully assigned high-level meanings. The RPC stub uses a separate destination
port-to-space conversion. These paths have different input objects and
conversion/reference frontiers. Neither their naming nor their convergence
establishes authorization for a particular live task port.

## Argument records and fallback message ABI

The original handler reads W0/W1/W2 from record offsets 0/8/16. The table's shared
three-word munger loads packed u32 values at 0/4/8 and stores zero-extended u64
slots at 0/8/16, in reverse order. The static algebra query proves that this
order preserves all three input words for every 24-byte input bit pattern.
It does not establish that the munger runs on the daemon's actual entry path.

| Representation | Extent / offsets | Evidence |
| --- | --- | --- |
| Public arguments | T,N,P are u32 | Handler W-register loads and SDK API types |
| Expanded selected argument record |24 B; T0,N8,P16 | Original munger loads/stores; analyst layout compile check |
| User fallback request |40 B; header 24,NDR 8,N at 32,P at 36 | Client stores/constants and SDK-sized layout |
| Kernel-form request |48 B | Original MIG stub size guard; retained 32-byte internal-header layout |
| User simple reply |36 B; expected ID3327 | Original client checks |
| Kernel nominal reply |44 B | Original subsystem routine metadata |
| Client receive capacity |44 B | Original W6 argument; capacity is distinct from inline reply size |

The user request uses header bits 0x1513, remote=T, local=mig_get_reply_port(),
voucher0 and request ID3227. Member N and set P are inline integers. The request
is simple; they are not transferred port descriptors. Task/reply transport
references and the named member/set rights therefore require separate lifetime
accounting. Both captured NDR constants are 0000000001000000.

The client calls mach_msg2_internal with options0x200000003 and send size 40 B.
Its store at offset 40 is outside the 40-byte request; it is not an extra inline
argument. This is the client call contract before lower transport/hook/retry
effects. The retained [transport report](kernel_rpc_transport_report.md) supplies
the distinct user/internal header context. This increment does not observe a
request, reply or representation conversion at runtime.

| Operation | Fast selector / u32 arguments | Client fallback request/reply IDs | User request / expected reply / capacity |
| --- | --- | --- | --- |
| extract_member | -23 /3 |3227 /3327 |40 /36 /44 B |
| deallocate | -18 /2 |3206 /3306 |36 /36 /44 B |
| mod_refs | -19 /4 |3208 /3308 |44 /36 /44 B |

All three client bodies are captured. The kernel MIG routine record is freshly
resolved for 3227 here; kernel MIG records for 3206/3208 are not re-resolved in
this increment. Original Mach trap records 18,19,22 and 23 are all rechecked.

## Kernel roles and lifetime boundaries

| Anonymous original entry | Inferred role / evidence |
| --- | --- |
| `0xfffffe000bcdbd34` | Extraction trap handler, identified by original Mach table |
| `0xfffffe000bcdffd8` | Common extraction core, called by fast handler and 3227 stub |
| `0xfffffe000bcc936c` | Pair lookup/type admission; member bit 17 and set bit 19 checked before returning objects |
| `0xfffffe000bd6d9c0` | Selected membership unlink; searches/updates member/set rings and returns link or null |
| `0xfffffe000bd7a4b8` | Returned-link storage free frontier, inferred from arguments and paired allocator class |
| `0xfffffe000bcde540` -> `0xfffffe000bcd3cfc` | Name deallocation core -> separate right-dispatch frontier |
| `0xfffffe000bcde6d8` -> `0xfffffe000bcd4250` | Right/delta modification core -> separate right-dispatch frontier |

The extraction core's direct callee set is pair lookup, unlink, object unlock
and returned-link free. It calls unlink with member/set queue subobjects, saves
the returned link, unlocks both objects and then frees a nonnull link using the
same allocator-class address0xfffffe0007e43358 used by insertion. It has no
direct call to either captured right-dispatch frontier. The unlink body's
ordinary path updates ring associations and returns link storage; its internal
consistency/error frontiers are retained without runtime interpretation.

These observations establish the explicit membership/storage operation. They
are not a complete proof of all transitive helper effects, unchanged native
reference counts or a live namespace's final contents. Namespace lookup,
locking, diagnostics, allocator and right-dispatch callees remain frontiers.
The original MIG path also performs temporary space-reference bookkeeping
around the core; that is a different reference scope from the member's receive
right and the CF object's lifetime.

## Return values and CF propagation

| Selected static condition / continuation | Value | SDK name / limitation |
| --- | ---: | --- |
| Fast task-name conversion returns null |0x10000003 | MACH_SEND_INVALID_DEST; selects library fallback |
| Extraction core receives null space |16 | KERN_INVALID_TASK |
| Extraction member or set is a null/dead sentinel name |17 | KERN_INVALID_RIGHT; assumes nonnull space |
| Pair admission's inactive/name continuation |15 | KERN_INVALID_NAME; lower lookup paths may return other values |
| Pair type-diagnostic continuation |17 | KERN_INVALID_RIGHT if diagnostic callee returns |
| Admitted pair has no matching membership link |12 | KERN_NOT_IN_SET |
| Admitted pair returns a link and free continuation returns |0 | KERN_SUCCESS |
| Deallocation core gets null/dead sentinel with nonnull space |0 | No-op continuation before ordinary name lookup |
| mod_refs core gets null/dead sentinel, selected RECEIVE right |15 | KERN_INVALID_NAME; different right kinds have separate branches |

The matched extraction sentinel guard rejects exactly u32 names0 and 0xffffffff;
the proof is over the arithmetic predicate, not namespace/type admission. The
same query checks the matched mod_refs B.HS guard variant. The
core also propagates the pair-lookup return. This table is a bounded source-local
catalog; it is not an exhaustive native error catalog or a reachability proof.

At CF 0x18477934c, immediately after the extraction call, original code loads a
new value into X0 and continues to source-set removal. The returned extraction
value is overwritten before a value test in that continuation. This supports
the earlier separation between CF association cleanup and membership status,
subject to the call returning normally and the stated runtime premises.

Earlier [combined service cases](daemon_service_cf_lifecycle_report.md) supplied
extraction statuses4 and 5 to test propagation/state boundaries. Those values
are not established native outcomes of this captured corridor. The new static
findings refine their interpretation; they do not convert prior fixtures into
native observations. The [CF lifetime report](cf_mach_port_retirement_report.md)
separately tracks destruction/cancellation and selected right-release requests.

## Verification and limits

The verifier freshly recaptures the original bytes, pointer records and data
constants. It checks 68 exact instruction assertions, four trap bindings, the
3227 routine record,96 syntactic direct call/tail edges and two unresolved
indirect sites. The edge set is bounded by the captured functions; it is not a
closed transitive call graph. Anonymous role labels remain inferences even when
the operation's table/export identity is exact.

Two retained negated-equivalence queries return UNSAT using the installed Z3
command-line solver 4.16.0. Its version, executable hash, invocation and exact
SMT2 text are retained. The first query checks the matched sentinel-name guard
variants over all u32 inputs. The second checks the fixed reverse record
expansion over all 192 input bits. These are algebra proofs, not kernel-state,
pointer-validity, concurrency, authorization or native-path proofs.

Four direct SDK headers are hashed and 24 arm64e compile assertions pass. They
cover public scalar widths/types, signed delta, sentinel/right constants,
selected 24/40/36-byte analyst layouts and API prototypes. Manual argument/message
layouts are analyst reconstructions checked against original access offsets;
they are not claims of a recovered original C declaration. The complete
transitive SDK/compiler installation is not hashed.

Twelve altered-evidence controls are rejected: extraction-to-insertion handler
substitution, argument count, munger store width, request ID, user request size,
reply ID, link-free target, sentinel return, receive type bit, kernel NDR,
kernel request size and algebra query. Fresh recapture uses the same readers;
the instruction checks, SDK compilation and SMT queries check different parts
of the resulting contract. They add no target execution or runtime observations.

Function bytes checked are (703 + 498) * 4 B = 4804 B. This count excludes separate
stub/metadata/constants and does not measure executed code. Static processing
costs O(I + E) time/space for I captured instructions and E direct edges.
Extraction/verification additionally reads and hashes source bytes and pointer
metadata; SMT/compiler costs are separate. Original membership search is linear
in the traversed member-link ring. No bound on native contention, lower lookup
cost or complete right-retirement work is established.

## Bounded continuation opportunities

| Impact | Remaining interface | Concrete evidence to obtain |
| --- | --- | --- |
| High | Native task/space and member/set identity | Correlate existing task/port observations with the two conversion paths and namespace ownership; avoid inferring identity from repeated numeric names. |
| High | Complete right/reference retirement | Account separately for CF references, temporary space references, membership-link storage and namespace right references using the remaining original callee paths. |
| High | Actual daemon/kext/deeper-facility transaction | Continue source-pinned interface/caller/ownership documentation across the retained user-client and FairPlay RPC boundaries; the ZUT failed-open trace still does not establish a successful transaction. |
| Medium | Complete diagnostic/conversion behavior | Recover unnamed conversion/diagnostic callees and their return/termination/reference contracts before treating source-local constants as an exhaustive native error catalog. |
| Medium | Queue readiness, waiting and concurrency | Correlate retained queue/link code with existing scheduler/receive evidence; association removal alone does not establish delivery, wakeup or concurrent lifetime effects. |
| Medium | Runtime status provenance | Compare any available return trace with namespace/type/membership prerequisites; preserve the distinction between observed returns and earlier supplied statuses4/5. |
| Low | Canonical internal nomenclature | Use original symbol/string/type records to refine anonymous role labels while preserving exact operation/table identities. |

## Quality gates

QG1: Pass for factual technical analysis; no normative conclusion is required.

QG2: Pass for this increment: KR1-KR8 list dependencies and falsification probes.

QG3: Pass for the bounded static CF/task-interface extraction, fast/fallback
convergence, record/wire ABI and membership/right-dispatch distinctions. The
full interface goal remains incomplete.

QG4: Pass: u32 values versus u64 slots, byte extents, arithmetic predicates,
SDK types, source counts and algorithm bounds are reproducible.

QG5: Pass within scope: direct versus transitive effects, returning diagnostic
premises, native identity/authorization, sentinel variants, status overwrite
and prior supplied-status limits remain explicit.

QG6: Pass: original kernel/cache bytes, chains, tables, exports, hashes, SDK
compilation, two SMT queries and altered controls are retained. Target visits,
target emulation and runtime observations are all zero.

QG7: Pass: bounded high/medium/low continuation opportunities are listed above.
