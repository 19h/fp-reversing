# Both-full retirement helper and magazine custody

The helper at `0xfffffe000bd75180` moves magazine buffers and returns the incoming cache C or zero. Every modeled normal nonzero return passes an explicit store of zero to the producer count at C+6. The original caller then stores the retired pointer at producer slot 0 and changes that count to 1. A different replacement cache is not produced by this body under the ordinary nonvolatile-register ABI. Native callee memory effects, synchronization, ownership and reclamation remain unknown. [RM1-RM7]

This resolves the return/reset source boundary left in the [zone-retirement report](kernel_zone_retirement_report.md) and connects it to the opposite buffer used by [allocation/refill](kernel_zone_refill_report.md). It remains a deeper kernel component; no additional Mach endpoint or right-emission site, native allocation identity or matching daemon transaction is established.

## Primary evidence and claim map

The original compiler-bounded body is `[0xfffffe000bd75180,0xfffffe000bd756f8)`, 350 instructions / 1,400 B, SHA-256 `5252f162f234fc4b77658b63c5f0c716b961c4ea9c2a9187fa508239f352c5ff`. Kernel collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Normalized predecessor kext SHA-256: `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. The complete preceding retirement body and allocation body exactly match their earlier captures. None of this helper and its eight direct call targets has an exact original symbol. Role names below describe source use or explicit call models. Local references suffice; no IDA/database mutation or native execution occurs.

| Claim | Established contract | Dependencies |
| --- | --- | --- |
| RM1 | Complete body, 14 direct call sites / eight targets, and whole-function return/reset provenance | RM-A1-A3 |
| RM2 | Allocation consumes C+4/C+8; retirement produces through C+6/C+0x10 | RM-A1-A4 |
| RM3 | Positive quota uses local empties first; exhausted local inventory can spill full magazines and gather shared empties | RM-A1-A5 |
| RM4 | Zero quota obtains a shared empty or requests a new raw magazine, then queues the old producer as shared full | RM-A1-A5 |
| RM5 | Marker subtraction, comparison request, CAS and lock-word byte effects have exact fixed-width source contracts | RM-A1-A6 |
| RM6 | Same-cache return plus count reset composes with the original caller's one-pointer publication under explicit noninterference/capacity premises | RM-A1-A7 |
| RM7 | Source CFG, instruction formulas and original-byte components have independent list/state checks and changed-source controls | RM-A1-A7 |

Evidence: [extractor](triage_evidence/recover_kernel_retirement_magazines.py), [instruction/CFG audit](triage_evidence/audit_kernel_retirement_magazines.py), [private CPU executor and independent list oracle](triage_evidence/probe_kernel_retirement_magazines.py), [delivery verifier](triage_evidence/verify_kernel_retirement_magazines_delivery.py), [capture](triage_evidence/kernel_retirement_magazines_checks.json.zst), [audit/components](triage_evidence/kernel_retirement_magazines_audit.json.zst).

Decoded capture SHA-256: `23222833dc8d0af1cf2ace9c02a13cd2c2eaea204b11e3fef72a8062137514bb` (90,781 B). Decoded audit SHA-256: `620ace6bb019692829a4d497f5f897d98bb83126ea5ee378aec044a16a8f6157` (2,814,867 B).

## Two active buffers and entry ABI

The caller requests this helper at `0xfffffe000bd7514c` with X0=zone Z, X1=selected cache C, X2=element P and X3=extent E. The helper retains C in X19 and Z in X20. Its source stores move magazine headers, links, counts and pointers; the caller performs the actual P publication after return. External call arguments beyond the identified operands are not assigned an undocumented callee meaning.

| Cache field | Allocation-side operation | Retirement-side operation |
| --- | --- | --- |
| u16 C+4 | Consumer count, decremented before pop | Opposite active count used by the earlier exchange gate |
| u64 C+8 | Consumer slot-array pointer | Opposite active slot-array pointer |
| u16 C+6 | Opposite active count | Producer count, reset here and incremented after return |
| u64 C+0x10 | Opposite active slot-array pointer | Producer slot-array pointer, installed here |
| u32 C+0x18 / C+0x1c | Local full / empty inventory counts | Same full / empty inventory counts |
| u64 C+0x20 / C+0x28 | Local head / full-prefix boundary link address | Same partition fields |

Thus the earlier reports' allocation-side and retirement-side “current/spare” names are relative to different operations. The offsets are consistent. The new source proof of `[0xfffffe000bd75ccc,0xfffffe000bd75ce8)` confirms allocation decrements C+4, reads C+8, returns the selected entry in X20, and clears its eight-byte slot. It preserves C+6 in the declared domain. The retirement publication block instead uses C+6 and C+0x10. [RM2]

Each selected magazine has a 16 B header followed by sixteen eight-byte slots: `16 B + 16*8 B = 144 B`. That size is a component premise derived from the selected capacity 16, rather than an attestation of native storage. Zone+0x48/+0x4c hold shared full/empty counts; +0x50 is the concatenated list head and +0x58 is the address of the link after the last full node. The cache uses the same full-prefix/empty-suffix convention at +0x20/+0x28. A zero full count makes the boundary the address of the head cell, not a NULL tail.

## Positive local quota

The helper reads Q=u16[Z+0x7c]. For Q>0 it requests the cache lock call at `0xfffffe000bd751b0`, then reads local empty count. An available local empty bypasses shared handling entirely, including the full-spill threshold. One selected case has four local full magazines and quota 2 but still takes this local-empty shortcut.

If local empty inventory is exhausted, the source enters shared-depot handling. When local full count F>=Q, it retains `floor(Q/2)` full magazines if the optional marker-object pointer at C+0x30 is zero; with a nonzero marker object it retains zero. It splices the removed full prefix into the shared full partition. The source updates u32 counts modulo 2^32; interpreting them as list lengths requires the declared list/count invariant.

With a marker object, Q!=1 and nonempty shared full inventory, a further gate may move `floor(Q/2)` shared full magazines back into local full inventory. Let M be u64 at the first shared full header+8 and A be u64 at the marker object. The gate computes D=`M-A mod 2^64` and compares D as signed:

| Exact predicate | Batch-transfer decision |
| --- | --- |
| signed64(D)<1 | Proceed directly with the batch |
| signed64(D)>=1 | Request 0xfffffe000bd37700; proceed iff returned W0 is nonzero |

This is not an unsigned M>A predicate, and no native clock interpretation is established. Components test a negative difference, modular wrap from A=0xffffffffffffffff, and comparison returns 0, 1 and 0xffffffff.

The source then gathers shared empties using `min_u32(Q-F, shared_empty_count)`. Under F<=Q this is the ordinary available-room minimum. It lowers the shared-empty sample at Z+0x6c when the new empty count is smaller. An available local empty is unlinked, its two header words are cleared, and its slot array is installed at C+0x10. C+6 becomes zero. The old producer header is appended at the local full-prefix boundary; full count increases and empty count decreases. Pop, install and queue instruction certificates expose their join operands separately; the full CPU components retain one uninterrupted source/RAM state.

If no empty is supplied, the source requests the raw magazine allocator with `(zone_view[0],zone_view[1],5)`, using the view pointer at `0xfffffe0007e66f58`. A nonzero returned header can be installed; zero selects helper return zero after the source unlock path. No native allocator effect or allocation success is inferred from the declared component results. [RM3]

## Zero quota, header provenance and followup

For Q=0, the helper checks shared empty count before entering the shared lock. If that count is zero, it first requests a raw magazine. After acquiring the shared word it either installs that returned header, removes a shared empty, or selects zero return if neither is available. This ordering is a source dependency; the ordinary components use a coherent shared-count snapshot and do not simulate an external writer between the two checks.

The old producer is added to shared full inventory. Security bit 12 selects insertion at the front; without that bit the source inserts at the full-prefix boundary. When the old shared full prefix is empty, the boundary is updated to the old producer header in either route. The shared-empty removal and marker CAS update precede this full insertion.

Header clearing depends on provenance. A popped empty passes a store clearing its first word before installation, and installation clears its second word. A raw allocator result joins after the first-word clear: only header+8 is explicitly zeroed here. Components initialize new raw storage with 0xa5 and verify that its first word remains `0xa5a5a5a5a5a5a5a5`; they supply no implicit allocator zeroing. The raw header's first word is not used as a next link while that buffer is active. [RM4]

The zero-quota success path also tests zone+0x3c bit 4. A set bit requests another lock at Z+0x80, rechecks the byte and may request `0xfffffe000bd75b54` with X0=Z before releasing that word. The selected followup model leaves RAM unchanged; the native followup's cache effects remain unknown.

## Architectural calls and source lock-word effects

| Target | Source sites | Recovered request / verification boundary |
| --- | --- | --- |
| 0xfffffe000bd0ae78 | 0xfffffe000bd751b0; 0xfffffe000bd75624 | Cache or Z+0x80 lock request; native acquisition unexecuted |
| 0xfffffe000bd0ab80 | 0xfffffe000bd7542c; 0xfffffe000bd75614; 0xfffffe000bd7567c | Source unlock-followup request; models preserve RAM |
| 0xfffffe000bd0abac | 0xfffffe000bd755b4; 0xfffffe000bd75648 | Shared contention request with lock word and class pointer 0xfffffe0007e63658 |
| 0xfffffe000beda010 | 0xfffffe000bd75604; 0xfffffe000bd756c0 | Instrumentation request `(handle,Z+0x60,0,0,0,0)` |
| 0xfffffe000bd75c64 | 0xfffffe000bd75458; 0xfffffe000bd75698 | Raw magazine allocation request; declared header/zero return |
| 0xfffffe000bd75b54 | 0xfffffe000bd75634 | Zone followup request `(Z)`; native effects unknown |
| 0xfffffe000bd37700 | 0xfffffe000bd756dc | Marker comparison `(object,header_marker,observed_marker,u64[object+8],0)`; W0 is the decision operand |
| 0xfffffe000c6336f8 | 0xfffffe000bd756f4 | Zone diagnostic `(Z)` from the [diagnostic report](kernel_retirement_diagnostics_report.md); this component stops before it |

The shared word at Z+0x60 is updated by LDADDA adding 0x01000000 modulo 2^32. The gate compares bytes 23..16 and 31..24 of the old word. Source release increments the byte at +2 modulo 256 using STLURB, preserving the other word bytes. The formulas prove sequential architectural read/modify/write values and branch operands. They do not establish native acquire/release ordering, exclusion, wait completion or ownership. Selected uncontended/contended shadow words finish as 0x01010000/0x01020000, with all external lock calls explicitly modeled.

The marker CAS compares object+8 with `header_marker-4 mod 2^64`; on equality it writes header_marker, and in either case its expected-value register receives the old object word. Components include matching and nonmatching cases. The phase byte at `0xfffffe000ca92380` gates the source event-counter increment following contention; phase 0 and 255 are separate declared epochs. Instrumentation handles and unlock-monitor state are explicit inputs, with no native callback execution. [RM5]

## Return provenance and caller composition

```text
both-full caller(Z,C,P,E)
           |
        Q == 0? --------yes----> shared empty / raw allocator
           | no                             |
      local empty? --yes--> pop/install      |
           | no                 |           |
      spill/gather/allocate ----+-----------+
                          /                  \
                       success             no header
                          |                  |
                  explicit count=0         X19=0
                  install producer           |
                  queue old producer         |
                          +--------+---------+
                                   |
                         common X0=X19; restore frame
                              /             \
                           X0=C             X0=0
                             |                |
                      caller stores P    deeper release(Z,P)
                      at producer[0]     nesting still held
                      count 0 -> 1
```

The whole-helper CFG has 350 nodes and 392 edges. A finite may-branch analysis visits 366 abstract states, treating ordinary external calls as preserving X19 and allowing volatile X0 to change. Its normal return states are exactly zero without a reset and C after a reset. This overapproximation covers every source location, including paths not executed by the components. It does not prove branch feasibility, loop/callee termination or callee RAM noninterference. The final diagnostic BL has a fallthrough outside the compiler interval if it returns; that edge is recorded, rather than silently assuming native nonreturn behavior.

The shared-boundary repair store at `0xfffffe000bd752ec` is not selected by the components. Under the stated marker/spill route, Q>1, F>=Q and a nonoverflowing shared-full-plus-F sum imply `shared_after_spill>=Q>floor(Q/2)`. A second composition proof therefore excludes removing that entire full prefix in this coherent, noninterfering epoch. This is a conditional exclusion, not a globally unreachable/native-dead-code claim; wrapping counts or callee/writer changes invalidate its premises. The other two unexecuted helper locations issue the zone diagnostic.

Successful local/shared installation stores zero to u16[C+6] at `0xfffffe000bd753d8` / `0xfffffe000bd754c0`. The common exit at `0xfffffe000bd75580` selects X0=X19 and restores its 80 B frame and saved registers. Together with the preceding 48 B caller frame, these captured bodies reserve 128 B; external callee frame depth is unknown. Replacing either reset instruction with NOP causes the abstract reset invariant to fail and yields a retained abstract counterpath. No mutated target or native instruction stream is executed.

With no intervening writer/callee change to C+6 and valid returned storage, the source zero count composes with the existing caller push. One append fits every positive u16 capacity K because `1<=K` for all K!=0. Positivity, storage and noninterference remain explicit premises. The helper's source reset resolves the missing local producer step; it does not prove the native capacity invariant by itself. Zero return joins the original deeper-release tail with `(Z,P)`, frame restored and thread nesting still 1 in the selected components. [RM6]

## Verification and assumption register

The audit combines the whole-function abstract certificate, 19 nonvacuous instruction obligations, two composition proofs and four predecessor rechecks. Two generic memory lemmas establish nonaliasing of disjoint nonwrapping regions and read-over-distinct-store preservation; five explicit range instantiations and 1,392 checked byte-read/store rewrites support the instruction interpreter. The 79 distinct block locations comprise 68 helper locations and 11 caller/allocation locations, with 96 instruction instances and 77 linked-edge obligations. All SMT counterexample queries are UNSAT. Local pop/install/queue certificates are modular source cuts; complete CPU components execute the original retirement tail and helper continuously. Explicit byte-separation lemmas are proved from the existing nonwrapping/disjoint region domains before they are supplied to the array solver, introducing no further address restrictions. Native memory ordering is outside these sequential formulas.

The 27 components make 5,186 source instruction visits and exercise 347 distinct helper locations; 25 return normally and two request deeper release. All 653 independent checks pass. The components import the published startup case-7 private RAM and image globals, then declare a new call epoch with recorded register/memory overlays. They retain the source-created ID-24 zone geometry but supply point metadata, both-full active buffers, inventory, thread state, control globals and raw allocator outcomes. This is not an exact held-PC continuation of the startup constructor and is not a native free of a startup allocation. Independent oracles compare partition counts, heads, boundary-link addresses, every resulting next link, header provenance, exact helper/comparison ABIs, return identity, caller publication, consumer preservation, marker effects, low-water/event state, accounting, nesting, frame restoration and opaque element bytes. Universal pop/push formulas declare separate 512 KiB slot windows to cover every u16 index; this is a proof domain, distinct from the 144 B magazines used by these components and from unknown native extents.

Recovery costs O(input bytes+I+S) time/space for instructions I and symbols S. The finite abstract analysis costs O(18*(V+E)) time and O(18*V) storage; the bound 18 is three X19 classes, three X0 classes and two reset-history states. CPU replay costs O(visits+RAM+journals); the list oracle costs O(nodes+checked bytes). Local formula construction is O(instruction instances+expression-DAG nodes), with 60 s per source-query and 30 s per separation/composition/predecessor-query limits. No solver complexity bound or numerical approximation is claimed.

| ID | Assumption and dependent result | Stress test / falsification probe |
| --- | --- | --- |
| RM-A1: source identity | Pinned original image, compiler intervals and predecessor matches identify this build. All claims depend on identity. | Rehash and recapture complete helper/caller/allocation bodies, blocks, globals and exact original symbols. |
| RM-A2: abstract/instruction semantics | The CFG transfer classes, fixed-width operations, byte arrays, preindexing and sequential atomics model the selected source. RM1-RM7 use this model. | Rebuild canonical formulas and CFG states, remove either actual reset word, and compare the original-byte CPU outcomes with independent list oracles. |
| RM-A3: ordinary call ABI | External calls return normally where replay continues and preserve nonvolatile registers/SP/caller storage. Return identity uses this premise. | Inspect actual callee code/ABI and native return behavior; preserve the recorded diagnostic fallthrough boundary if nonreturn is unproved. |
| RM-A4: storage/geometry | Declared cache/zone/header/slot/stack windows are valid, nonwrapping and disjoint as stated; slot arrays have the selected extent. Source memory claims depend on this domain. | Prove byte-separation consequences, verify actual mappings/aliases and match native zone/cache/header ownership independently. |
| RM-A5: list and component epoch | Counts match finite full-prefix/empty-suffix lists; overlays define coherent new-call snapshots. RM3-RM4 and CPU results use these fixtures. | Check every count/head/boundary/next link, vary local-empty availability, quotas, security bit, allocator zero/nonzero outcomes and head-cell versus node boundaries. |
| RM-A6: marker/lock environment | Marker values, phase/monitor globals and external comparison decisions are declared; no native ordering or clock identity is inferred. RM5 uses this boundary. | Vary signed/wrapped differences, comparison returns, matching CAS, contention, phase 0/255 and monitoring; recover writers and native lock contracts separately. |
| RM-A7: publication noninterference | Reset-to-push composition assumes intervening callees/writers preserve count/storage, positive K and the stated caller frame. RM6-RM7 are conditional on these facts. | Recover followup/lock callees, match their RAM effects and K/storage in one native epoch, then correlate the daemon request and allocation identity. |

## Bounded continuation

| Impact | Next evidence | Unresolved question |
| --- | --- | --- |
| High | Deeper release at 0xfffffe000bd756f8 | Actual metadata/page updates, reclamation, nesting custody and reuse |
| High | Followup 0xfffffe000bd75b54 and lock/monitor callees | Which source reset values survive real external effects and synchronization |
| High | Matched daemon request, userclient record and kernel buffer epoch | Which actual transaction reaches these magazine paths |
| Medium | Marker object producer and comparison callee 0xfffffe000bd37700 | Units, ordering and actual ownership of the two marker words |
| Medium | Magazine allocator view and returned storage | Native 16 B header/slot extent, initialization and failure contract |
| Low | Larger quotas and inventory lists | Additional finite cases beyond the recorded quota/list bounds |

## Scoped quality gates

- **QG1**: Factual control/data-flow and machine-interface claims only.
- **QG2**: RM-A1-RM-A7 identify assumptions, dependencies and falsification probes.
- **QG3**: Complete helper CFG, all call sites, both active buffers, inventory policy, reset/return provenance and caller handoffs are covered within their stated proof/component scopes. The full interface goal remains active.
- **QG4**: 350*4 B=1,400 B; 80 B+48 B=128 B; 16 B+16*8 B=144 B; u8/u16/u32/u64 arithmetic and signed modular marker interpretation are explicit.
- **QG5**: Source-store provenance versus current RAM, normal returns versus termination, new-call fixtures versus exact held continuation, sequential atomics versus native synchronization, and popped versus raw header clearing remain distinct.
- **QG6**: Original bytes, predecessor matches, source formulas, whole-CFG states, changed-source controls and original-byte components with independent list/state oracles provide reproducible provenance.
- **QG7**: Ranked continuation covers deeper release, external effects, transaction identity, marker producers, raw storage and larger inventory domains.
