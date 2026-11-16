# Deeper zone release: bitmaps, metadata queues and nesting custody

The original routine at `0xfffffe000bd756f8` records a released element by setting one previously clear bitmap bit, decrementing a u16 metadata count, and conditionally relinking the leading metadata record. Its ordinary tail requests the lock-release routine at `0xfffffe000bd0ab18`, whose original bytes decrement thread nesting and select an ordinary return or pending continuation. This closes the source nesting handoff left by the [retirement tail](kernel_zone_retirement_report.md) and [both-full magazine helper](kernel_retirement_magazines_report.md). Physical page reclamation, native exclusion, external callee effects and a matching daemon transaction remain unknown. [BR1-BR7]

This is a deeper kernel contract reachable through the earlier [allocator boundary](kernel_allocator_boundary_report.md), [small retirement dispatch](kernel_retirement_dispatch_report.md) and [MixedData retirement](mixed_data_retirement_report.md). It establishes no additional Mach endpoint, transmitted right or daemon-visible reply. The full interface investigation remains active.

## Primary evidence and claim map

The original kernel collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; the normalized predecessor kext SHA-256 is `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Compiler function boundaries establish these complete captures:

| Function interval, end exclusive | Instructions | Bytes | SHA-256 |
| --- | --- | --- | --- |
| 0xfffffe000bd756f8..0xfffffe000bd75b54 | 279 | 1,116 B | dbb8a61d87e167397507f945798b1ae04f9731525f71f1b4c65f373a2ccbc319 |
| 0xfffffe000bd0ab18..0xfffffe000bd0ab80 | 26 | 104 B | 270d0acea36c72afbda7c759201b2708232fdf173802e063a84ed0cf388b81e6 |

The complete earlier 109-word retirement body and 350-word magazine helper match their published captures. Neither new entry nor any of the ten distinct external targets has an exact original symbol. Descriptive names in this report denote recovered source roles. No new IDA observation was required.

| Claim | Established source contract | Dependencies |
| --- | --- | --- |
| BR1 | Entry ABI, release-lock ticket operation, point/zone validation and leading-record selection | BR-A1-A4, BR-A7 |
| BR2 | u64 product, high-u32 index and exact extent/displacement equality gate | BR-A1-A4 |
| BR3 | External 64-bit and inline 32-bit bitmap address, free-bit rejection and single-bit update | BR-A1-A4 |
| BR4 | Count store precedes underflow check; zero and occupancy threshold select metadata queues | BR-A1-A4 |
| BR5 | Signed predecessor encoding, reciprocal-link checks, unlink/insert effects and zone counters | BR-A1-A5, BR-A7 |
| BR6 | Source release tail transfers nesting custody to unlock; pending bit2 selects continuation | BR-A1-A3, BR-A6-A7 |
| BR7 | Local instruction proofs, bounded composition, whole-state component checks and changed-store controls | BR-A1-A7 |

Evidence: [extractor](triage_evidence/recover_kernel_zone_bitmap_release.py), [instruction audit](triage_evidence/audit_kernel_zone_bitmap_release.py), [CPU components and independent oracle](triage_evidence/probe_kernel_zone_bitmap_release.py), [delivery verifier](triage_evidence/verify_kernel_zone_bitmap_release_delivery.py), [capture](triage_evidence/kernel_zone_bitmap_release_checks.json.zst), [audit](triage_evidence/kernel_zone_bitmap_release_audit.json.zst). Decoded capture SHA-256: `9c92ce8ad5dfa3bdbbee5b55b9de96b332dff83f677c7cd107506a2f2ecc65db` (71,726 B). Decoded audit SHA-256: `30c1cc9abbe3076303416504298a51540cee36ef1351acf5841639e07cc77078` (5,106,457 B).

## Entry, environment and leading metadata

| Entry operand | Meaning recovered from source |
| --- | --- |
| X0 | Zone Z |
| X1 | Element address P |
| SP | Caller SP; release saves 48 B |
| TPIDR_EL1 | Thread-context source used subsequently by unlock |

At `0xfffffe000bd75718`, `LDADDA` adds `0x01000000` to u32[Z+0x80] modulo 2^32 and returns the old word. The source compares old bits23..16 against old bits31..24. Inequality requests the contention callee with X0=Z+0x80, W1=old bits31..24 and X2=`0xfffffe0007e63658`; its native synchronization behavior is unknown. On that branch, phase byte `0xfffffe000ca92380` equal to zero, a null raw/authentication-result cache, and u32[Z+0x8c]<u32[Z+0x84] select a modular increment of u32[Z+0x74]. Raw nonnull cache authentication uses the earlier slot-derived `0x8b6b` modifier. Native authentication is unproved. An uncontended nonzero acquire-monitor handle from `0xfffffe000cb115b0` requests instrumentation with `(handle,Z+0x80,0,0,0,0)`.

The point predicate is `L <=_u P <_u U`, using globals at `0xfffffe0007e66e50` and +8. It does not validate P+extent. For root R=u64[`0xfffffe0007e66f00`], J=`R+((P>>10) AND 0xffffffff0)`, and H=u16[J], the source requires `0xfffffe000caeb480+192*(H AND 0x3ff)==Z`.

Let E=u16[Z+0x34] and initially d=`(P AND 0x3fff)-u16[Z+0x36]` modulo 2^64. If `(H AND 0xf000)==0xe000`, B=u8[J+2] extends d by `B*16384 B` and selects a leading record M=`J-16*B` modulo 2^64. If `((J XOR M) AND 0xffc0000000000000)!=0`, the source replaces M's high 16 bits with `0xc8a2`. Otherwise it retains M. The inline/external bitmap flag and count are read from the selected leading record, not necessarily J. Exact tag arithmetic is proved; native pointer validity and the occurrence of its changed-tag branch are unknown. [BR1; BR-A3-A4]

## Quotient, bitmaps and count order

For multiplier Q=u64[Z+0x28], the source forms p=`Q*d mod 2^64`, k=`p>>32` and requires `u64(k)*u64(E)==d`. This full-width reconstruction check is separate from the preceding retirement routine's low-u32 modular gate. Two bounded composition obligations establish k=`floor(d/E)` and acceptance iff d mod E=0 for E in {128,256} B and 0<=d<32768 B. No general reciprocal-division interpretation is asserted for other multipliers, extents or wrapped displacements. [BR2]

| Leading-record bit11 | Bitmap word address A | Mask b | Width |
| --- | --- | --- | --- |
| Clear | u64[0xfffffe0007e66e70] + 8*(u32[M+4] AND 0x0fffffff) + 8*(p>>38) | 1 << (k AND 63) | 64 bits |
| Set | M + 16*(p>>37) + 4 | 1 << (k AND 31) | 32 bits |

Both layouts request the bitmap diagnostic if `word AND b != 0`. Otherwise XOR sets the single clear bit and preserves all other bits. The external store is at `0xfffffe000bd75810`; the inline store is at `0xfffffe000bd75838`. This source polarity supports the descriptive term free-bit map. Native ownership and whether the element corresponds to a currently allocated object remain unknown. [BR3]

The count sequence is exact:

```text
n = u16[M+2]
t = u32(n) - 1                  modulo 2^32
u16[M+2] = low16(t)              store at 0xfffffe000bd75844
if t AND 0xffff0000: diagnostic  equivalent here to n == 0
if low16(t) == 0: move M to Z+0x98 queue
else if E*((n AND 0x7fff)+1) > ((u16[M] << 2) AND 0x3c000):
    move M to Z+0x9c queue
else: retain queue membership
```

The underflow branch therefore observes a count already stored as `0xffff`; it follows the bitmap store. This is an instruction-order result, not evidence that native zero-count input is reachable. The threshold uses the old count's low15 bits plus one. Source components distinguish old counts 63 and 64 at E=256 B with a 16 KiB span, and also exercise raw old count0x8000. The span expression is a byte extent with 16 KiB steps. [BR4]

## Encoded queues and state publication

The leading record carries u32 next at M+8 and u32 predecessor at M+0xc. Its own index I is low32(`(M-R)>>4`). A nonzero next index N addresses `R+16*N`; the source checks that node's predecessor equals I before storing the old predecessor there.

Predecessor interpretation uses a signed32 comparison against 1. If predecessor S>=1 signed, the target is a four-byte sentinel cell derived from G=`0xfffffe000ca8c000`: `G-4+4*S`. A sign-extension consistency check on the scaled offset selects either that ordinary address or the low48 bits of the unsigned address with high16 replaced by `0x2bad`. If S<=0 signed, the target is the next field at `R+16*zero_extend(S)+8`. The old target must contain I before receiving N. Native valid-index ranges and the address-tag fallback domain remain unknown. [BR5]

For destination head cell D=Z+0x98 (new count zero) or Z+0x9c (threshold transition), the insertion sequence is:

1. Clear the entire eight-byte link pair at M+8.
2. Store old u32[D] into M+8.
3. If that old head is nonzero, check its predecessor equals `low32((D-G+4)>>2)` and replace that predecessor with I.
4. Store that sentinel encoding at M+0xc, then I at D.

Moving to Z+0x98 additionally adds `u16[M]>>12` to u32[Z+0x90] modulo 2^32. Queue identity as empty-span versus nonempty-available metadata is an interpretation of the branch predicates; physical page removal or return to a VM allocator is not performed by any newly modeled external callee. A subsequent consumer of the Z+0x98 queue remains a reclamation frontier.

Reciprocal-link failures can occur after earlier stores. The independent oracle checks the exact partial state at each selected diagnostic request, including a repaired old successor preceding a bad predecessor and the partially installed link pair preceding a bad destination backlink. It also checks unchanged queue state on paths without reclassification. Native recovery or termination after those requests is unknown.

## Outgoing interfaces and thread custody

| Destination | Emission site | Recovered ABI / condition |
| --- | --- | --- |
| 0xfffffe000bd75b54 | BL 0xfffffe000bd75aa4 | X0=Z when zone byte+0x3c bit4 is set; callee RAM effects unmodeled |
| 0xfffffe000bd0abac | BL 0xfffffe000bd75ac0 | Contention `(Z+0x80,old ticket byte,class pointer)` |
| 0xfffffe000beda010 | BL 0xfffffe000bd75b28 | Acquire instrumentation `(handle,Z+0x80,0,0,0,0)` |
| 0xfffffe000c633aa0 | BL 0xfffffe000bd75b38 | Point/zone/displacement rejection; X0=Z, X1=P |
| 0xfffffe000c633728 | BL 0xfffffe000bd75b3c | Reciprocal-link rejection; X0=Z, X1=M |
| 0xfffffe000c633c7c | BL 0xfffffe000bd75b44 | Existing free-bit rejection; X0=Z, X1=P |
| 0xfffffe000c6338dc | BL 0xfffffe000bd75b50 | Count underflow; X0=Z, X1=M, X2=0xfffffe0007053a00 |
| 0xfffffe000bd0ab18 | Tail B 0xfffffe000bd759d8 | Release frame restored; X0=Z+0x80 |
| 0xfffffe000bd0ab80 | BL 0xfffffe000bd0ab68 | Nonzero unlock-monitor handle selects a callee request with X0=lock address |
| 0xfffffe000c63aec8 | BL 0xfffffe000bd0ab70 | Unlock observes zero thread nesting; no local decrement |
| 0xfffffe000be8663c | Tail B 0xfffffe000bd0ab7c | Decrement reaches zero and pending-object byte+0x4c bit2 is set; frame restored |

The two captured bodies contain nine BL sites, one tail internal to the two-body capture, and one tail beyond it; they reach ten distinct external targets. Diagnostic names describe source branch roles, not native callee outcomes. If a diagnostic callee returns, its compiler fallthrough remains possible; components stop at the first request and do not claim native nonreturn.

Before its tail, release increments u32[Z+0xa8] modulo 2^32. Unlock uses a separate 16 B frame, increments only lock byte+2 modulo 256 with STLURB, optionally requests its monitor followup, and reads T=TPIDR_EL1. It rejects u32[T+0x1c8]==0; otherwise it decrements that word. A nonzero result returns. A zero result reads the pending pointer at T+0x1c0 and selects the pending continuation when byte+0x4c bit2 is set. Source memory order and single-thread byte effects are established; lock exclusion and inter-CPU ordering are not. [BR6]

```text
retirement: nesting++ ; extent accounting
       |
       +-- null cache / helper zero --> deeper release(Z,P)
                                      |
                            validate ; set free bit
                            count-- ; queue transition
                                      |
                             event++ ; tail unlock
                                      |
                       owner byte++ ; nesting gate
                           /                 \
                     zero: diagnostic       decrement
                                        /              \
                                   still >0         reaches0
                                    return        pending bit2?
                                                 /          \
                                               clear        set
                                              return    continuation
```

Two components execute the original retirement prefix with a raw-null cache; a third executes the original both-full helper through a declared null raw-magazine allocation, then the actual deeper release and unlock bytes without resetting RAM/register state at either handoff. These verify the conditional increment/decrement and extent-accounting join. Fixtures start a new explicit epoch from startup case7 with overlays; they do not establish a native free of the earlier startup allocation. External ordinary calls preserve the ABI, clobber volatile registers and have no RAM effects by explicit model. Native callback interference can invalidate a corresponding whole-state result. [BR-A5-A7]

## Verification and assumption register

Sixteen source counterexample queries are UNSAT with satisfiable premises. They cover 66 source PCs, 107 instruction instances and 91 linked-edge obligations. Two bounded quotient/alignment composition queries and two previously published generic separation lemmas are UNSAT. The shared byte-array model records 200 read-over-store rewrites justified by disjoint nonwrapping storage regions and the rechecked array lemma.

The 66 private components execute 7,507 original instruction visits, including caller/helper bytes, and 304 of the 305 PCs in the two new captured bodies. All 897 independent oracle checks pass. The sole unexecuted captured PC is the changed-tag MOVK at `0xfffffe000bd757b8`; its exact conditional arithmetic is covered by source proofs. This coverage union is not a universal whole-routine proof. The oracle reconstructs every non-stack private-RAM byte and the full 192 B zone, including partial diagnostic states, and independently checks frame/nonvolatile restoration, bitmap/count/queue fields, counters and thread state. Source writes into opaque element storage are not observed in these components.

Replacing either actual bitmap store with NOP in a separate private instruction copy causes the independent oracle to reject the exact bitmap word. These are changed-source CPU controls, not solver SAT claims, native executions or vulnerable-state reproduction.

Extraction costs O(B+I+S) time/space for image bytes, instructions and symbol records. Formula construction costs O(I+Q) time/space for instruction instances and query-DAG nodes. Component replay/oracle costs O(V+J+R) time/space for source visits, journals and RAM. SMT search has a separate 30 s per-query limit. All counts, byte extents and arithmetic widths are exact. Inline all-product proofs use a nonwrapping 2 GiB metadata arena as a sufficient storage domain; this is not a measured native allocation size. CPU fixtures use only their selected private metadata words.

| ID | Assumption and dependent result | Stress test / falsification probe |
| --- | --- | --- |
| BR-A1: source identity | Pinned collection, compiler bounds and predecessor captures supply all instructions. BR1-BR7 depend on identity. | Recapture both complete functions and both prior bodies; compare hashes, instruction inventories and exact symbols. |
| BR-A2: instruction model | Fixed-width operations, variable shifts, flags, preindexing and byte-array rewrites represent the selected instructions. BR2-BR4, BR6-BR7 use this model. | Rebuild/re-solve formulas, recheck separation lemmas and compare the independent CPU; reject both changed bitmap stores. |
| BR-A3: storage/authentication | Declared nonwrapping/disjoint regions and selected words are valid. PAC/AUT returns and cache AUTDA use logical identity envelopes in components. BR1-BR7 are conditional. | Establish native mappings, aliases and authentication separately; exercise overlap/wrap alternatives before extending the source contract. |
| BR-A4: metadata/geometry epoch | Zone, root, count, layout and multipliers belong to the declared snapshot. Quotient interpretation is limited to the two proved extents/domain. BR1-BR4 use this premise. | Match P/Z/J/M/E/Q in one epoch; test non-power-of-two and wrapped-displacement domains independently. |
| BR-A5: queue coherence | Selected links/counts and snapshot stay stable except for executed source stores. BR5 and whole-state components depend on this premise. | Match native list heads/reciprocal links and writers; selected next/previous/destination inconsistencies must stop with the exact partial stores. |
| BR-A6: thread context | The supplied thread/nesting/pending objects remain coherent. BR6 and linked increment/decrement components use this premise. | Verify native TPIDR_EL1 identity, CPU migration and pending writers; nesting0/1/2 and pending bit2 cases distinguish the branches. |
| BR-A7: external execution | Declared ordinary external calls have no RAM effects; diagnostics/continuations stop at request boundaries. Native synchronization, reclamation and daemon correlation are unknown. BR1, BR5-BR7 retain these limits. | Recover followup/lock/monitor/pending callees and queue consumers; correlate a native daemon/userclient/kernel epoch before claiming end-to-end behavior. |

Reproduction uses the relative extractor, audit and verifier entrypoints with `PYTHONPATH=triage_evidence` and the installed Capstone, Unicorn and Z3 packages. The verifier freshly reconstructs captures, formulas, components and mutation controls, then verifies owned-file deltas, original inputs, archive custody and decoded path hygiene.

## Bounded continuation

| Impact | Next evidence | Remaining question |
| --- | --- | --- |
| High | Followup at 0xfffffe000bd75b54 and its observer/notification boundaries | Actual flag updates, callbacks and memory interference across release/helper epochs |
| High | Consumers of Z+0x98 and source queue/counter writers | Whether/when empty-span bookkeeping becomes physical page reclamation or reuse |
| High | Matched daemon request, userclient buffer and kernel allocation epoch | Which external transaction reaches the recovered release contract |
| Medium | Contention, lock and monitor callees | Native exclusion, preemption and memory-order guarantees |
| Medium | Pending continuation at 0xfffffe000be8663c | Scheduling and incoming context beyond the local nesting/bit predicate |
| Low | Tagged-address fallback and general reciprocal domains | Native initialized domains supporting broader pointer/index interpretations |

## Scoped quality gates

- **QG1**: Factual source/ABI/control/data-flow claims only.
- **QG2**: BR-A1-BR-A7 give assumptions, dependencies and falsification probes.
- **QG3**: Both complete captures, selected source proofs, queue/state components, external emission sites and thread handoff are reported. The broader interface goal remains active.
- **QG4**: 279*4 B=1,116 B; 26*4 B=104 B; 305 captured words; 48 B release frame and 16 B unlock frame; 192 B zone; 16 B metadata stride; 16 KiB page step; exact u8/u16/u32/u64 arithmetic.
- **QG5**: Bookkeeping versus physical reclamation, old versus new count, partial diagnostic stores, signed index interpretation, conditional authentication and source versus native concurrency are explicit.
- **QG6**: Original pinned bytes, prior body matches, reconstructed canonical formulas, independent whole-state checks and two altered-source controls provide provenance.
- **QG7**: Impact-ranked continuation covers observers, reclamation, native synchronization, scheduling, transaction identity and arithmetic-domain expansion.

The [paired zone observer/event protocol](kernel_zone_observer_event_report.md) establishes bit4 arm/clear stores, observer controls1/0 with post-callback next reloads, the shared Z+0x20 wait/wake hash and registration/unlock/block/reacquire request order. Seventeen source proofs and 65 private components retain explicit native callback, authentication, synchronization, scheduling, reclamation and daemon-epoch limits; no additional Mach endpoint is established.
