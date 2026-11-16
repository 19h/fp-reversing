# Permanent storage behind zone statistics and per-CPU caches

Subsequent evidence: The [physical-zero report](kernel_physical_zero_report.md) establishes an explicit selected refill zero request and the complete zero-wrapper source contract, with private byte/replay checks. The ready-path preservation results below remain valid; native allocation-to-zero identity is still unknown.

The original routine at0xfffffe000bd71a20 supplies the32 B statistics and64 B cache requests previously represented by opaque storage-return models. Its ready-page path rounds a request, selects a16 B metadata record, updates cursor/usage/free-space/per-CPU counters, optionally moves the page between encoded queues, and constructs the return from a signed32-bit page index. It does not clear the returned payload on that path. The cache initializer also leaves the current/spare u16 magazine counts unchanged. Consequently zero-filled backing remains an explicit prerequisite, rather than a property established by either of these routines. No native uninitialized-memory defect or usable initialized cache is asserted. [PS1-PS6]

```text
fixed slot1 request: vm.permanent        -> setup record -> flag0x100, extent1
fixed slot2 request: vm.permanent.percpu -> setup record -> flag0x100, extent1
       [full fixed-slot construction and backing production remain open]

declared ready slot2 + metadata + nonzero backing
  |
  +-> original permanent allocator(32,7) -> statistics pointer PAGE
  |     original magazine-zone creator -> view stores that exact pointer
  |
  +-> declared new-call epoch, exact predecessor state transfer
        original cache initializer
          +-> original permanent allocator(64,63) -> cache pointer PAGE+64
          +-> typed magazine returns [explicit zero-storage models]
          +-> per-CPU pointers/control fields written
          +-> u16 counts at+4/+6 preserve backing bytes
```

## Primary provenance and claim register

Kernel collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Normalized kext SHA-256: `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Original compiler intervals, instruction bytes, literals and format8 fixups are the primary sources. None of the six functions has an exact nlist name in this capture; routine/record role names are descriptive. Original reference data sufficed; no new IDA access or modification was required.

| Complete interval, end exclusive | Instructions | Bytes | Role |
| --- | ---: | ---: | --- |
| 0xfffffe000bd71a20..0xfffffe000bd71c10 | 124 | 496 | Permanent storage allocator |
| 0xfffffe000bd77ce4..0xfffffe000bd77d00 | 7 | 28 | Fixed slot1 setup callback |
| 0xfffffe000bd77b94..0xfffffe000bd77bb0 | 7 | 28 | Fixed slot2 setup callback |
| 0xfffffe000bd772b4..0xfffffe000bd77b94 | 568 | 2272 | Zone creator; exact prior-capture match |
| 0xfffffe000bd77bb0..0xfffffe000bd77ce4 | 77 | 308 | Cache initializer; exact prior-capture match |
| 0xfffffe000c6324a0..0xfffffe000c632708 | 154 | 616 | Magazine bootstrap; exact prior-capture match, selected consumer cuts only |
| Total | 937 | 3748 | Twelve selected blocks contain90 instructions |

| Claim | Established result | Dependencies |
| --- | --- | --- |
| PS1 | Original routine/call-site inventory and setup-record/fixup custody | PS-A1, PS-A2 |
| PS2 | Modular rounding, ready-page selection, accounting, signed-index return and refill boundary | PS-A1, PS-A3, PS-A4 |
| PS3 | Fixed setup records select identical flag/extent callbacks through original constructor ABI | PS-A1, PS-A3 |
| PS4 | Original32/64 B storage calls inside publication/cache components and retained backing/count bytes | PS-A1, PS-A3-PS-A5 |
| PS5 | Source proofs, finite whole-state oracles, independent replay and source-mutation rejection | PS-A1-PS-A6 |
| PS6 | Native initialization, ownership and daemon/kext interface limits | PS-A1-PS-A6 |

Artifacts: [extractor](triage_evidence/recover_kernel_permanent_storage.py), [private executor and oracle](triage_evidence/probe_kernel_permanent_storage.py), [independent replay](triage_evidence/replay_kernel_permanent_storage.py), [source audit](triage_evidence/audit_kernel_permanent_storage.py), [delivery verifier](triage_evidence/verify_kernel_permanent_storage_delivery.py), [capture](triage_evidence/kernel_permanent_storage_checks.json.zst), [audit receipt](triage_evidence/kernel_permanent_storage_audit.json.zst). Decoded capture SHA-256: `8eff8d54ed8fefa4b82296e4fd234a65283fdf9fe0f66b35c39079f8954ff97d` (398179 B). Decoded audit SHA-256: `62aed64859e94b47d50286145c1b4a9feea01b4ab4de458421e3b6b69082343a` (5053652 B).

The immediate B/BL scan rehashes725 executable spans and checks15,490,987 aligned words, locating85 direct sites targeting the allocator. The inventory includes actual creator calls at0xfffffe000bd77438/0xfffffe000bd7746c and cache call0xfffffe000bd77c0c. It does not exhaust indirect/data references or establish the arguments/path feasibility at all85 callers. [PS1]

## Exact allocator contract

At entry X0=zone Z, X1=request S, X2=alignment mask A. Let u64 arithmetic wrap modulo2^64. The original prefix computes Q=(S+A)&~A. When A=2^k-1 and the addition does not overflow, Q rounds S upward to a multiple of2^k; arbitrary masks retain the raw bitwise contract. X2 is not identified as a generic flag word here: the two consumers pass7 and63. [PS2]

| Storage | Address / offset | Width / meaning |
| --- | --- | --- |
| Slot2 allocator Z | 0xfffffe000caeb600 | Zone-array slot2; prior initialization declared |
| Metadata translation base T | u64[0xfffffe0007e66f00] | Base for16 B metadata records |
| Ready queue head | Z+0x9c | u32 page index |
| Full queue head | Z+0xa0 | u32 page index |
| Free-space counter | Z+0xa8 | u32, decremented by low32(Q) |
| Statistics base | u64[Z+8] | Current CPU's counter at base+(u16[TPIDR_EL1+0x1b8]<<14) |
| Selected record R | T+16*zero_extend_64(index) | Sixteen bytes |
| Used quantity | R+2 | u16 |
| Cursor | R+4 | u32 |
| Next / previous encoding | R+8 / R+12 | u32 queue links |

A zero ready head calls the original refill routine0xfffffe000bd71c10 with X0=Z, W1=0. Otherwise the allocator scans candidates and admits a page only if `(Q+zero_extend_64(cursor)) mod2^64 <= 16384` unsigned. Nonfitting candidates advance through R+8; an exhausted chain requests refill. The private cases stop before the refill body. Its effects, progress and native payload initialization remain unknown. [PS2]

For an admitted candidate, aligned=(A+cursor)&~A. The original stores are:

| Original PC | Exact effect |
| --- | --- |
| 0xfffffe000bd71aa4 | u32[R+4]=low16(aligned+Q), zero-extended into the32-bit slot |
| 0xfffffe000bd71ab0 | u16[R+2]=(old used+Q) mod2^16 |
| 0xfffffe000bd71abc | u32[Z+0xa8]=(old free-Q) mod2^32 |
| 0xfffffe000bd71ad8 | u64[current CPU statistics]=(old statistics+Q) mod2^64 |
| 0xfffffe000bd71be0..0xfffffe000bd71bf0 | Return=(sign_extend_64(low32(index))<<14)+zero_extend_64(low16(aligned)), modulo2^64 |

The fit test uses Q+old cursor; the returned offset additionally aligns that cursor. Valid native request/cursor constraints are therefore separate premises. Raw controls cover a nonstandard mask, wrapped request rounding, free-counter underflow and statistics overflow; they are not asserted valid native requests. Cursor movement can include an alignment gap while usage/free/statistics counters account for Q alone. [PS2]

## Queue transition and ready-path preservation

After debit, the source shifts the u16 used value right3 and compares it with0x7ff. Values below16376 bypass movement; values at least16376 unlink the selected page from its current queue and push it onto Z+0xa0. Previous-link values are interpreted as signed32: positive values encode a u32 head at `0xfffffe000ca8c000-4+4*previous`; nonpositive values address a preceding metadata record's R+8 through zero-extended index arithmetic. Source backlink checks precede their corresponding updates; mismatch requests original diagnostics. Private positive cases establish only coherent list inputs. [PS2]

The finite oracle covers ready-head removal, a remaining next page, insertion before an existing full-queue node, and removal of a second candidate after skipping an insufficient first page. It checks entire records, queue heads and boundary guards. These witnesses supplement the local source proofs; they are not a universal proof of every queue topology or native synchronization. [PS2,PS5]

The ready allocator's stores target stack, metadata, zone counters, queue links and the selected statistics counter. Under the declared disjoint-region premise, the debit proof preserves an arbitrary byte of the16384 B raw payload. Complete positive ready-path executions additionally preserve the entire nonzero raw backing. Lock callees are explicit no-RAM return models. The refill path is not executed, so this does not establish whether native refill or an earlier mapping operation zeros backing. [PS2,PS6]

## Fixed records, callbacks and constructor requests

| Bootstrap call PC | Original name | Extent argument | Flags | Fixed ID | X4 setup record |
| --- | --- | ---: | --- | ---: | --- |
| 0xfffffe000c6325c0 | `vm.permanent` at0xfffffe000705352d | 1 | 0xe000000044000020 | 1 | 0xfffffe0007e66fc0 |
| 0xfffffe000c6325e8 | `vm.permanent.percpu` at0xfffffe000705353a | 1 | 0xe000000045000020 | 2 | 0xfffffe0007e67000 |

Each32 B record contains a first authenticated pointer to0xfffffe000cb5c7e0, scalar0x50000000 at+8, a function pointer at+0x10 and an associated-data pointer at+0x18. The first pointer uses key2/diversity0x6ae1/address diversity; the function pointer uses key0/diversity0/address diversity. Associated-data pointers use key2/diversity0xc0bb/address diversity and target0xfffffe0007e66fa0 for record1,0xfffffe0007e66fe0 for record2. Logical targets are explicit format8 interpretations; native authentication is untested. [PS3]

The constructor loads the function from `[record+0x10]`, passes X0=record and X1=zone, and executes BLRAA at0xfffffe000bd776b8 with the function-pointer slot address as modifier. Record1 targets0xfffffe000bd77ce4; record2 targets0xfffffe000bd77b94. Both complete seven-instruction callbacks OR0x100 into u32[zone+0x3c], set u16[zone+0x34]=1 and return. The callbacks do not allocate backing or zero a payload. The record type/class name and associated-data semantics remain unknown. Full fixed-slot construction and full magazine bootstrap are outside these components. [PS3]

## Source storage calls and initialization dependency

The publication cut executes original magazine-zone creation, including its actual allocator(32,7), and publishes the source-created view. The next component transfers exact predecessor private RAM and recorded image regions, resets the call frame under a declared new-call epoch, supplies separate IPC-zone geometry and executes the complete original cache initializer including actual allocator(64,63). No ownership or successful native startup is inferred from this transfer. Typed magazine storage remains an explicit zero-storage model. [PS4]

| Capacity K | Numbering bound N | Current CPU index | Source statistics return | Source cache return | Publication / cache source visits |
| ---: | ---: | ---: | --- | --- | --- |
| 8 | 1 | 0 | 0xfffffe0007d00000 | 0xfffffe0007d00040 | 246 /133 |
| 10 | 2 | 1 | 0xfffffe0007d00000 | 0xfffffe0007d00040 | 246 /153 |
| 14 | 3 | 2 | 0xfffffe0007d00000 | 0xfffffe0007d00040 | 233 /173 |

These addresses are declared private backing, not observed native allocations. The selected metadata cursor advances0 ->32 ->128; used advances0 ->32 ->96. The32 B alignment gap is preserved. The creator stores the exact32 B return at zone+8; typed magazine requests subsequently reuse that source-produced statistics pointer and leading view. Statistics payload bytes remain their nonzero input values. [PS4]

At each CPU cache slot, the initializer writes the current/spare pointers at+8/+0x10, a16 B vector at+0x18, a self-linked list pointer at+0x28, and control0x144 at+0. It does not overwrite the u16 magazine counts at+4/+6. In the declared affine backing fixture those counts remain0xbead and0xe0cf for every selected CPU slot, exceeding K in all three cases. This deliberately invalidates an unstated empty-cache premise; it is not evidence that native backing has those contents. The preceding [magazine-bootstrap report](kernel_magazine_bootstrap_report.md) used explicit zero-storage models, which satisfy this prerequisite within their private scope. The native zero-initialization producer is still to be established. [PS4,PS6]

## Verification and bounds

Fourteen nonvacuous source queries are UNSAT over89 distinct PCs/89 instruction instances and75 linked-edge obligations. They cover rounding, head/fit/next decisions, debit and arbitrary disjoint payload-byte preservation, the full threshold, signed-index return, both setup callbacks, both32/64 B request ABIs, both fixed constructor requests and cache-count preservation by its vector/list/control stores. Two prior separation lemmas are rechecked;32 read-over-distinct-store rewrites are checked. These are local block contracts, not a universal proof of the complete124-instruction allocator or every queue topology. [PS5]

Twenty-one components comprise13 direct allocator cases,2 complete setup callbacks and3 publication/cache pairs. They pass173 independent semantic checks, execute2044 visits over401 of937 captured PCs, and enter the original permanent allocator19 times. Seventeen entries return; two stop before refill. The two independent epochs in each pair are explicit, while each constructor-to-allocator and cache-initializer-to-allocator call executes in one original stack without replacing that allocator by an API model. [PS4,PS5]

Fresh replay imports no new executor/audit. It checks2044 visits,432 writes/2850 B,491 reads/3077 B,21 boundaries,22020096 final private-RAM bytes,942478 recorded final-region bytes and36 independently reconstructed allocator events. Sixty-six remaining model calls are checked against explicit lock or typed-magazine contracts. Forty-eight source PAC steps and3 PACDA envelopes remain logical treatments. Three NOP controls fail the semantic oracle: cursor store0xfffffe000bd71aa4, setup extent store0xfffffe000bd77cf8 and cache-pointer publication0xfffffe000bd77cb4. [PS5]

Extraction costs O(collection bytes + scanned words + source + fixups) time/space. Proof construction costs O(source + formula DAG); solver search is separate with30 s per query. Execution/replay costs O(visits + journals + mapped state), with20000 instructions maximum per component and1048576 B private RAM per CPU instance, plus explicitly mapped source/backing pages. Integer calculations are exact little-endian u16/u32/u64 operations; no floating-point error bound applies. Native physical page backing and actual initialized values remain unknown. [PS5]

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PS-A1: Pinned original image, compiler intervals, byte decoding and format8 logical targets | PS1-PS6 | Rehash collection/source and725 spans; recapture six functions/records and compare three retained bodies; independently re-decode six authenticated pointer words |
| PS-A2: Immediate aligned B/BL inventory is the stated discovery domain | PS1, PS6 | Verify all85 source words/targets; indirect calls, data references and unrelated argument paths require separate work |
| PS-A3: Declared disjoint metadata, zones, statistics, raw backing and logical PAC/call ABI | PS2-PS6 | Nonvacuous source premises, separation lemmas, guard bytes, full-RAM replay and all source mutations; native aliases/authentication failures invalidate a native join |
| PS-A4: Coherent encoded queues and valid native request/cursor constraints are separate premises | PS2, PS4-PS6 | Head/next/full-tail/second-candidate cases, request wrap, nonstandard mask and accounting wrap; recover actual refill/metadata producer before claiming native admission or progress |
| PS-A5: Exact predecessor state transfer and declared new-call IPC geometry; locks have no RAM effects and typed magazine backing is zero | PS4-PS6 | Reconstruct transfer and all66 model contracts; preserve nonzero statistics/count bytes and alignment gap; native constructors, exclusion and typed allocation effects remain separate obligations |
| PS-A6: Source proofs, semantic oracle and fresh CPU replay cover recorded cuts/cases only | PS5, PS6 | Compare original bytes and every read/write/event/final region; three changed-source cases must fail; full refill/bootstrap/daemon transactions are unexecuted |

## Architectural scope and bounded continuation

This increment refines backing prerequisites for kernel IPC-zone cache/allocation paths already linked to the kext investigation. It establishes no new Mach name, receive/send right, right transfer, endpoint or message-emission location. The [Mach-port report](mach_ports_report.md) and [ABI report](interface_abi_report.md) retain their separate interface evidence. Native backing initialization, ownership, synchronization, successful boot and a matched fairplayd/provider/kernel transaction remain unknown. [PS6]

| Impact | Bounded continuation | Evidence still required |
| --- | --- | --- |
| High | Establish the native zero/backing producer before treating cache counts or statistics as initialized | Original refill0xfffffe000bd71c10, mapping/page-initialization helpers and their actual metadata/publication epoch |
| High | Execute full fixed slot1/2 construction and magazine bootstrap with source backing effects | Existing setup records, VM-range preparation, early statistics migration and coherent page queues in one stack |
| Medium | Extend coherent queue witnesses to a whole-CFG/path proof including backlink failures and refill returns | All conditional queue edges, exact diagnostic/return contracts, termination and native exclusion |
| Medium | Integrate original startup callbacks and policy producers with these backing contracts | Phase/cursor order, rank1/rank2 effects, unchanged capacity/memory/topology epochs and dynamic IDs |
| High | Correlate one daemon/user-client/provider/kernel transaction | Matching images, request/response bytes, rights, statuses, ownership and observed epoch |

## Quality gates

**QG1** passes: factual technical analysis requires no normative content. **QG2** passes: PS-A1-PS-A6 specify dependencies and falsification probes. **QG3** passes for this increment: allocator ABI, fixed setup records/callbacks, queue/accounting behavior, consumer joins and Mach boundaries are covered; the full goal remains active. **QG4** passes: widths, byte units, modular arithmetic, signed index,16384 B page limit,16376 threshold and complexity are explicit. **QG5** passes: ready versus refill paths, logical versus native authentication, count preservation versus zero prerequisites and new-call versus continuous stacks are distinguished. **QG6** passes: original bytes/fixups, source queries, independent oracles/replay and source controls provide provenance. **QG7** passes: bounded impact-ranked continuation is recorded. `full_goal_complete=false`.
