# Paired zone observers, wait registration and release wakeup

The original routine at `0xfffffe000bd7332c` and the [release followup](kernel_zone_bitmap_release_report.md) at `0xfffffe000bd75b54` implement paired source interfaces around zone bit4 and event `Z+0x20`. The arm path sets bit4, invokes observers with control1, requests `_assert_wait(event,8)`, releases the zone+0x80 lock through the recovered nesting tail, requests blocking and tails to reacquire. The followup clears bit4, invokes observers with control0 and hashes the same event for a wake-all request. Native observer registration/effects, authentication, locking, waiter membership, blocking, wake delivery and daemon correlation remain unknown. [OE1-OE7]

This connects the deeper allocator protocol to the existing [event registration](aes_event_registration_report.md), [global wait-table startup](event_wait_table_report.md) and [wake selection](aes_event_wake_selection_report.md) contracts. Shared wait-queue code does not establish a Mach port identity. No additional port endpoint, transmitted right or message emission is established; the full interface goal remains active.

```text
arm(Z)                                      release followup(Z)
  cache/prefill early-return gate               clear bit4
  existing bit4 can bypass observers            observer(index,Z,0)
  set bit4 under requested zone+0x60 lock          |
  observer(index,Z,1)                             |
            |                                    |
  assert_wait(Z+0x20,8)                 hash(Z+0x20,root,count)
            |                                    |
  unlock(Z+0x80)                         wake(queue,event,0,0,-1)
  block(0,0,0)                                   |
  tail acquire(Z+0x80)                    original request-builder boundary
```

## Primary evidence and claim map

Original kernel collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Normalized predecessor kext SHA-256: `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Compiler function boundaries supply the complete captures below.

| Role | Preferred interval, end exclusive | Words / bytes | SHA-256 |
| --- | --- | --- | --- |
| New arm body | 0xfffffe000bd7332c..0xfffffe000bd73458 | 75 / 300 B | ea0ce2c04c6fcd0aace40c0329960d1efddabbf503c3b5a36c1ca43cdbe7328c |
| New followup body | 0xfffffe000bd75b54..0xfffffe000bd75c64 | 68 / 272 B | 0826396e807e213139e78ee6a7a44d866dfa047ac634b89c43110016c5575da0 |
| Reused _assert_wait | 0xfffffe000bd28394..0xfffffe000bd284d0 | 79 / 316 B | a15a363c1f8da0e7bd96b1690ac36f0ac70ba6f67d1d00e1bb2bf924db5e3e98 |
| Reused wake wrapper | 0xfffffe000bd6e22c..0xfffffe000bd6e310 | 57 / 228 B | 54418f1efeed296651d08db0b0d8bb679ef8b5487cf3e0ebbbaaf726a15cd574 |
| Reused unlock/nesting tail | 0xfffffe000bd0ab18..0xfffffe000bd0ab80 | 26 / 104 B | 270d0acea36c72afbda7c759201b2708232fdf173802e063a84ed0cf388b81e6 |

The three reused bodies exactly match their prior captures. The two new entries and observer root have no exact original nlist definition. `_assert_wait` has an exact definition in `com.apple.kernel`; other role names here are descriptive. Reference data sufficed, so no new IDA access or mutation was required.

| Claim | Established contract | Dependencies |
| --- | --- | --- |
| OE1 | Arm gates, bit4 publication, registration/unlock/block/reacquire request order | OE-A1-A4, OE-A7 |
| OE2 | Followup clears only bit4 before observers; no native post-callback flag guarantee follows | OE-A1-A4, OE-A7 |
| OE3 | Observer geometry/index, authenticated raw target/modifier/arguments and post-callback successor reload | OE-A1-A5, OE-A7 |
| OE4 | Same full event, shared hash and table-epoch dependency; ordinary and tagged addresses | OE-A1-A3, OE-A6 |
| OE5 | Wake wrapper/request-builder ABI and conditional raw return/frame custody | OE-A1-A3, OE-A6-A7 |
| OE6 | File/logical root provenance, bounded reference scan and unknown registration/writers | OE-A1, OE-A4-A5 |
| OE7 | Local source proofs, predecessor rechecks, whole-state private components and changed-store controls | OE-A1-A7 |

Evidence: [extractor](triage_evidence/recover_kernel_zone_observer_event.py), [source audit](triage_evidence/audit_kernel_zone_observer_event.py), [private CPU and independent oracle](triage_evidence/probe_kernel_zone_observer_event.py), [delivery verifier](triage_evidence/verify_kernel_zone_observer_event_delivery.py), [capture](triage_evidence/kernel_zone_observer_event_checks.json.zst), [audit receipt](triage_evidence/kernel_zone_observer_event_audit.json.zst). Decoded capture SHA-256: `64cf3d39a1796076cf55ae3933bcd555e2672133076980bf24ac95c3a7fbbeb4` (68,230 B). Decoded audit SHA-256: `be279f8e583e57a51c4d69424ab4560fdd528331f32463d32e47f54c5bec92c8` (5,654,919 B).

## Arm entry, flags and outgoing control

Both new entries receive X0=zone Z and save 48 B, including X19-X22 and FP/LR. The arm body tests the raw/authenticated cache at Z+0x40 with the earlier slot-derived `0x8b6b` modifier. If that cache is nonzero and quota u16[Z+0x7c] is nonzero, it requests `0xfffffe000bd730f8(Z)`. Bit0 of ordinary returned W0 selects an early return; W0 values0 and2 continue, while1 and0xffffffff return in the selected components. Native cache authentication and prefill effects are unestablished.

Otherwise the source tests byte[Z+0x3c] bit4. If already set, it bypasses flag publication and observer traversal but still reaches wait registration. If clear, it requests the zone+0x60 lock, then ORs `0x10` into the full u32[Z+0x3c] at `0xfffffe000bd73398`. It does not repeat the bit test after that lock request. Source byte+0x62 is incremented modulo256 with STLURB; a nonzero monitor handle at `0xfffffe000cb0bc50` requests unlock followup before reading the observer root. This does not prove exactly-once notification across competing armers. [OE1]

The selected ordinary path calls `_assert_wait(Z+0x20,8)`, then unlocks Z+0x80, requests `0xfffffe000bd28f6c(0,0,0)`, and restores its frame before tailing to `0xfffffe000bd0aab4(Z+0x80)`. There is no local test of the registration return value before the block request. This is distinct from the earlier workloop mutex-sleep result gate. Native block admission, registration success and lock ownership remain unknown. Raw control8 has low two bits zero; its complete symbolic/native flag name is not inferred.

Block/reacquire requests require the intervening unlock to return normally. Its nesting-error and pending-continuation branches remain as recovered in the preceding report; the selected arm components declare nesting1 and pending bit2 clear.

Block and reacquire are role descriptions inferred from this source order and the earlier scheduling interfaces. Their callee bodies and native effects are outside this increment.

| Destination | Emission site | Recovered request |
| --- | --- | --- |
| 0xfffffe000bd730f8 | BL 0xfffffe000bd73368 | Optional cache/prefill boundary, X0=Z; result bit0 selects early return |
| 0xfffffe000bd0ae78 | BL 0xfffffe000bd7338c | X0=Z+0x60 |
| Observer loaded from node+8 | BLRAA 0xfffffe000bd733fc | W0=index low16, X1=Z, W2=1, modifier X17=0xeed9 |
| _assert_wait / 0xfffffe000bd28394 | BL 0xfffffe000bd73410 | X0=Z+0x20, W1=8 |
| 0xfffffe000bd0ab18 | BL 0xfffffe000bd73418 | X0=Z+0x80; original unlock/nesting body executes in components |
| 0xfffffe000bd28f6c | BL 0xfffffe000bd73428 | X0=X1=W2=0 |
| 0xfffffe000bd0aab4 | Tail B 0xfffffe000bd73440 | X0=Z+0x80; frame restored; callee effects unexecuted |
| 0xfffffe000bd0ab80 | BL 0xfffffe000bd73448 | X0=Z+0x60 for nonzero monitor snapshot |
| 0xfffffe000c6336f8 | BL 0xfffffe000bd73454 | Rejected observer geometry, X0=Z |

## Followup publication and observer ABI

The followup clears only bit4 of the full u32[Z+0x3c] at `0xfffffe000bd75b74`, then reads the same root at `0xfffffe0007f213e0`. Observer nodes carry next at +0 and raw callback pointer at +8. A zero root bypasses both geometry checking and callbacks. For a nonzero root, both routines use D=`Z-0xfffffe000caeb480 mod 2^64` and reject `(D>>7)>0x40a`. This is exactly unsigned D>=132480 B. The guard admits an address interval; it does not independently require 192 B alignment.

Both compute K=`((D*0x01555556) mod 2^64)>>32` and pass low16(K). A separate integer composition proves that, for 0<=D<132480 B, the product does not overflow u64 and K=floor(D/192). Consequently aligned source zones in that interval correspond to IDs0..689. Callback index24 in the selected fixtures follows from the declared ID24 zone. [OE3]

| Observer field / call property | Arm | Followup |
| --- | --- | --- |
| Callback pointer | u64[node+8] | u64[node+8] |
| Preferred call site | 0xfffffe000bd733fc | 0xfffffe000bd75bc0 |
| Raw W0 | low16(K) | low16(K) |
| X1 | Z | Z |
| Raw W2 | 1 | 0 |
| X17 modifier | 0xeed9 | 0xeed9 |
| Next-pointer reload | 0xfffffe000bd73400 | 0xfffffe000bd75bc4 |

BLRAA target authentication is uninterpreted in source proofs and a logical call boundary in components. Neither the actual authenticated target nor native observer identity is established. Observer return W0 is not tested by either loop. Both preserve the current node in a nonvolatile register and load its next field after the callback returns. Source traversal therefore uses post-callback memory; it is not a frozen initial list. Acyclic list length and callback noninterference are additional premises for finite traversal or persistent flag claims.

The independent components include declared observer effects that clear/set bit4 after source publication, skip the second of three nodes, or truncate traversal after the first node. Their separate model-write journals identify those effects explicitly. The original instructions consume the changed link and retain the changed flag. These are interface-dependency controls, not evidence that any native observer performs those writes. [OE2-OE3; OE-A5,OE-A7]

## Shared event hash, wrapper and table epoch

After its observers, followup sets E=`Z+0x20` and reads B=u64[`0xfffffe0007e66df8`] and N=u32[`0xfffffe0007e66e00`]. Its source hash is identical to the ordinary `_assert_wait` hash applied to E:

```text
a = ((E XOR (E >> 31)) * 0x7fb5d329728ea185) mod 2^64
b = ((a XOR (a >> 27)) * 0x81dadef4bc2dd44d) mod 2^64
i = low32(b XOR (b >> 33)) AND (N - 1 mod 2^32)
o = zero_extend(i) * 24
if o == sign_extend(low32(o)):
    queue = B + o mod 2^64
else:
    queue = ((B + o) AND 0x0000ffffffffffff) OR 0x2bad000000000000
```

Both source blocks are proved against this expression for every u32 N, including zero. Under identical E/B/N snapshots they select the same queue. Positive power-of-two N and N<=2^26 supply the earlier bounded index/sign-fit/record-extent guarantees. Native table publication, epoch stability and backing remain separate premises. Hash equality is not waiter identity or membership; the reused wake-selection contract still compares the full event and queue identity. [OE4]

Followup restores its 48 B frame before the tail B at `0xfffffe000bd75c58`, with `(X0=queue,X1=E,W2=0,W3=0,W4=0xffffffff)`. Thus its input result and flags are raw zero, and its maximum is the full u32 all-ones word. No `_thread_wakeup_prim` return translation is inserted on this direct wrapper route. Under an ordinary request-builder return, a direct followup returns that raw builder word; selected snapshots 0,3,0xffffffff are preserved. The enclosing release path instead resumes its own remaining code. [OE5]

The reused original wake wrapper checks queue nonnull and byte+5 bit0 before locking queue+4. Queue types 1/2 additionally inspect the declared DAIF snapshot: bit9 clear requests the original diagnostic; otherwise missing bits from0x1c0 select DAIFSET #7 and add request flag0x10. Other types bypass that mask path. The source request-builder boundary at `0xfffffe000bd6c59c` receives `(queue,E,0,4 or 0x14,0xffffffff)`. The independent components stop at diagnostics or use an explicitly modeled ordinary builder result with no RAM effects. They do not execute queue scanning, actual masking, waiter removal or scheduler delivery. The prior report supplies those separate conditional source contracts.

The arm's reused `_assert_wait` hash is exercised with its trace-hook byte at `0xfffffe000cb5c400` declared zero. At its original registration-wrapper tail `0xfffffe000bd28448`, `(queue,E,8,deadline0)` is retained. Trace-hook paths are captured but not newly composed. Registration return snapshots 0,2,0xffffffff all reach the same subsequent source block request when the actual unlock returns normally. None proves successful native registration.

## Observer root provenance and locator limits

The root slot at `0xfffffe0007f213e0` belongs to `com.apple.kernel`'s `__DATA_CONST,__const`. Its eight original bytes and logical-file bytes are zero, and it has no chained-rebase record. This does not establish runtime emptiness, immutability or the absence of a registration facility. [OE6]

The retained locator scans `__TEXT_EXEC`, `__TEXT_BOOT_EXEC` and `__KLD`: 10,234,244 B / 2,558,561 aligned words. It identifies 48 ADRPs for the root's page, then considers same-base immediate accesses within 192 B. The only two resulting candidates are the root loads in these complete bodies at `0xfffffe000bd733b8` and `0xfffffe000bd75b7c`. No store appears in that candidate set. This is a bounded lexical locator, not a complete writer census: aliases, other address formations, register clobbers, other fileset code and indirect writes are not closed. Native observer installation and identities remain unknown.

## Verification and assumption register

Seventeen source counterexample obligations are UNSAT with satisfiable premises. They cover 119 source PCs, 131 instruction instances and 114 linked-edge obligations. The source branch target for BLRAA remains uninterpreted. Two composition queries establish the bounded reciprocal arithmetic and common hash contract; ten predecessor queries recheck hash bounds, full identity/event tests, request fields and return arithmetic. Two generic separation lemmas are rechecked for model provenance; this increment performs zero region-based read/store rewrites.

The 65 private components execute 9,014 original instruction visits, cover all 143 PCs in the two new bodies, issue 84 modeled observer requests and pass 811 independent checks. Coverage is across declared cases, not a universal all-path proof. The oracle independently reconstructs all non-stack private RAM and the full 192 B zone, and checks observer ordering/arguments, flag words, hash addresses, request-builder ABI, selected diagnostics, source release accounting, nesting and saved GP/SP custody. The actual retirement/deeper-release/followup/unlock bytes are linked without a state reset in release components. These start a new explicit epoch using startup case7 plus recorded overlays; no native allocation identity is inferred.

Ordinary modeled external calls preserve the ABI and clobber volatile registers. They have no RAM effects except the separately journaled observer controls. Logical PAC/BLRAA/AUTDA and DAIF snapshots are models. Replacing either actual flag store with NOP in a separate private source copy makes the independent flag oracle reject the result. These are CPU mutation controls, not SMT SAT claims or native reachability evidence.

Extraction/locator work costs O(B+I+S) time/space for source bytes, instructions and symbol records; the fixed 192 B window contributes a constant scan factor. Formula construction costs O(I+Q) time/space for instruction instances and query DAGs. Private replay/oracle costs O(V+J+R) time/space for visits, journals and RAM. A stable finite observer chain requires O(k) traversal for k nodes, excluding callbacks; mutated/cyclic chains and native scheduling have no established termination bound. SMT search is separate with a 30 s per-query limit.

| ID | Assumption and dependent result | Stress test / falsification probe |
| --- | --- | --- |
| OE-A1: source identity | The pinned collection, compiler bounds, exact symbols/fixups and reused captures supply all bytes. OE1-OE7 depend on identity. | Rehash/recapture all five bodies, the root slot and bounded locator scan; compare prior function bytes and symbols. |
| OE-A2: instruction model | Fixed widths, shifts, flags, frames and memory/call semantics represent the selected source. OE1-OE5 and OE7 use this model. | Freshly reconstruct/re-solve formulas, compare the independent CPU/oracle, and reject both altered flag stores. |
| OE-A3: storage/ABI | Declared valid, nonwrapping/disjoint regions and ordinary saved-register/frame rules hold. PAC/BLRAA/AUTDA remain conditional models. OE1-OE5 and OE7 are conditional. | Verify native mappings, aliases, stack extent, authentication and ordinary return custody separately. |
| OE-A4: zone/flag epoch | Z/flags/cache/quota belong to the declared epoch. Geometry is an interval guard, not a separate alignment proof. OE1-OE3 and OE6 use this premise. | Match initialized zone identity and concurrent writers; distinguish cache result bit0, preexisting bit4, root-zero bypass and unaligned-address admission. |
| OE-A5: observer memory | Nodes/callback targets and successor storage are valid; traversal uses post-callback next. OE2-OE3 and OE6-OE7 do not assume native callback noninterference. | Recover registration/teardown and actual callbacks; compare declared flag/link controls, aliases, cycles and reclamation across call/return. |
| OE-A6: event-table/thread epoch | Wait/wake share E/B/N when hash identity is used; selected queues and thread/pending objects are coherent. OE4-OE5 and linked source components use this premise. | Match runtime root/count and waiter event/identity; test different epochs, invalid counts/validity, DAIF gates, pending context and source admission separately. |
| OE-A7: external execution | Ordinary lock/prefill/registration/block/builder callbacks use declared return/effect snapshots. Native observer effects, synchronization, scheduling, reclamation and daemon correlation are unknown. OE1-OE3 and OE5-OE7 retain these limits. | Recover callees and correlate one daemon/userclient/kernel allocation, wait, release and resumption epoch before extending claims to native completion. |

Reproduction uses the relative extractor, audit and verifier entrypoints with `PYTHONPATH=triage_evidence` and the installed Capstone, Unicorn and Z3 dependencies. The delivery verifier freshly reconstructs captures, canonical formulas, components and mutation controls, then checks exact owned-file custody, compressed receipts, original inputs and decoded path hygiene.

## Bounded continuation

| Impact | Next evidence | Remaining question |
| --- | --- | --- |
| High | Observer root writers, registration/teardown and installed nodes | Actual callbacks, their lifetimes and possible interference with flag/cache/list state |
| High | Block/reacquire and optional prefill callees with matched thread/zone context | Native sleep admission, lock/nesting ownership and source caller context |
| High | Consumers of the empty-metadata queue and same daemon/userclient/kernel epoch | Physical reclamation/reuse and transaction-level behavior |
| Medium | Trace-hook paths, native DAIF/lock boundaries and queue epochs | Extra effects and visibility before registration/wake |
| Medium | Matched registration, selected waiter and returned scheduler result | Actual blocking/wakeup correspondence for event Z+0x20 |
| Low | Expand bounded root locator to aliases/other filesets | A stronger observer-writer census; current two-reader result is explicitly incomplete |

## Scoped quality gates

- **QG1**: Factual source/ABI/data/control-flow analysis only.
- **QG2**: OE-A1-OE-A7 give assumptions, dependencies and falsification probes.
- **QG3**: Both complete new bodies, three matched reused bodies, flags/observers, paired hash, request emission sites and conditional return custody are covered. The full interface goal remains active.
- **QG4**: 75*4 B=300 B; 68*4 B=272 B; 305 captured words=1,220 B; 48 B new frames; 192 B zone stride; 24 B queue stride; u8/u16/u32/u64 arithmetic and bounded-domain interpretation are explicit.
- **QG5**: Initial versus post-callback state, source requests versus native admission, interval versus alignment, same-hash versus full identity, raw8 control, pending branches and source coverage limits remain distinct.
- **QG6**: Original bytes/symbol/fixup provenance, predecessor matches, fresh formulas, independent RAM/ABI checks and two changed-source controls provide reproducible evidence.
- **QG7**: Ranked continuation includes callback registration, native blocking/locking, reclamation, trace hooks, epochs and transaction identity.

The [zone prefill and incoming-call study](kernel_zone_prefill_callers_report.md) establishes two counted list partitions, a source Boolean return and the continuous prefill-to-wait-arm early-return join. It locates three direct prefill calls and two direct wait-arm calls across all 15,490,987 scanned aligned executable words, and recovers the smaller caller's acquire/refill/wait-arm/unlock context. Nine local source proofs and 66 private components pass 708 independent checks; native provider effects, synchronization, scheduler admission, physical reclamation and daemon transaction identity remain unknown. Existing acquire and block-wrapper evidence is reused; no additional Mach endpoint is established. The full goal remains active.

The [per-CPU magazine drain](kernel_magazine_depot_drain_report.md) now identifies the actual full/empty partition producer used by prefill, two direct callers with zero/u16 quota controls, output ordering and the paired zone-bit2 operations. Original cache acquire/unlock bodies execute inside continuous drain/prefill/arm components. Sixteen local source proofs, one composition query and 38 private components pass 241 independent checks. Native cache/storage production, synchronization, full bulk processing, scheduling, reclamation and daemon transaction identity remain unknown; no new Mach endpoint is established. The full goal remains active.
