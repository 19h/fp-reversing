# Permanent refill, page-list mapping and ready publication

The selected original refill path now connects page acquisition, explicit payload clearing, page-list consumption, lower mapping requests, accounting and ready-metadata publication in one continuous private source cut. Exact output states then feed the original magazine-zone creator and per-CPU cache initializer in declared new-call epochs. The original permanent allocator supplies their32 B statistics and64 B cache storage; both magazine counts remain zero in every checked CPU slot. This is a conditional source/model join. Native physical aliases, lower mapping effects, page ownership and complete refill/boot execution remain unknown. [RP1-RP7]

```text
declared refill frame, empty slot2 and page-object fixtures
  original cut0xfffffe000bd72b40
    page acquisition [explicit return model]
    original physical zero wrapper -> original memset of declared aliases
    source-linked object list, newest object first
    original page-list consumer -> original per-page mapping adapter
      lower mapping requests [explicit result/no-RAM model]
    original accounting helper + current-CPU counter
    original metadata inserter -> ready head, cursor0, used0
  cut ends0xfffffe000bd72ae0
    |
    +-> exact state transfer, declared new-call epoch
          original magazine-zone creator -> original allocator(32,7)
          original view publication, statistics=PAGE
            |
            +-> exact transfer, declared new-call epoch
                  original cache initializer -> original allocator(64,63)
                  cache=PAGE+64; counts remain zero
                  typed magazines and locks retain explicit leaf models
```

## Primary provenance and claims

Original kernel collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Preserved normalized kext SHA-256: `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Primary sources are original bytes, compiler function intervals, nlist records and independently checked source effects. Reference data sufficed; no new IDA access or modification was required. [RP1]

| Complete interval, end exclusive | Instructions | Bytes | Role |
| --- | ---: | ---: | --- |
| 0xfffffe000bd71c10..0xfffffe000bd73084 | 1309 | 5236 | Refill; selected continuous cut only |
| 0xfffffe000be7b5b8..0xfffffe000be7b9b4 | 255 | 1020 | Physical-range zero wrapper |
| 0xfffffe000c648170..0xfffffe000c648218 | 42 | 168 | Original `_memset` |
| 0xfffffe000bdc12cc..0xfffffe000bdc15a8 | 183 | 732 | Page-list consumer |
| 0xfffffe000bdc15a8..0xfffffe000bdc17e4 | 143 | 572 | Per-page lower mapping adapter |
| 0xfffffe000bd73b5c..0xfffffe000bd7465c | 704 | 2816 | Metadata initialization/insertion |
| 0xfffffe000bd71a20..0xfffffe000bd71c10 | 124 | 496 | Permanent ready-page allocator |
| 0xfffffe000bd01454..0xfffffe000bd016d8 | 161 | 644 | Accounting helper |
| 0xfffffe000bd772b4..0xfffffe000bd77b94 | 568 | 2272 | Magazine-zone creator |
| 0xfffffe000bd77bb0..0xfffffe000bd77ce4 | 77 | 308 | Cache initializer |
| 0xfffffe000c6324a0..0xfffffe000c632708 | 154 | 616 | Bootstrap; selected publication cut |
| Total | 3720 | 14880 | Sixteen selected spans contain92 instructions |

Seven complete functions match prior captures byte-for-byte. Only0xfffffe000c648170 has an exact nlist identity among these eleven functions: `_memset`, com.apple.kernel, n_type15/n_section19. No exact name is recovered for the acquisition leaf0xfffffe000be100ec, lower mapping leaf0xfffffe000be5b2e8, list helpers0xfffffe000be0d098/0xfffffe000be0f308, or page-check leaf0xfffffe000be2f16c. Their role labels describe caller-side use, rather than recovered symbol names or complete native implementation contracts. [RP1,RP7]

| Claim | Established result | Dependencies |
| --- | --- | --- |
| RP1 | Original routine/byte custody, prior matches and exact name bounds | RP-A1 |
| RP2 | Same page-object/PFN sequence reaches zero and lower mapping requests | RP-A1-RP-A4 |
| RP3 | Per-CPU geometry, metadata/header/queue publication and capacity units | RP-A1, RP-A2, RP-A5 |
| RP4 | Accounting-helper classification and selected counter effects | RP-A1-RP-A5 |
| RP5 | Source-produced ready storage feeds actual statistics/cache allocation bodies | RP-A1-RP-A6 |
| RP6 | New proofs, prior-query rechecks, byte oracles, replay and source controls | RP-A1-RP-A7 |
| RP7 | Native, whole-refill, environment and Mach-interface limits | RP-A1-RP-A7 |

Artifacts: [extractor](triage_evidence/recover_kernel_refill_publication.py), [continuous executor/oracles](triage_evidence/probe_kernel_refill_publication.py), [independent replay](triage_evidence/replay_kernel_refill_publication.py), [source audit](triage_evidence/audit_kernel_refill_publication.py), [delivery verifier](triage_evidence/verify_kernel_refill_publication_delivery.py), [source capture](triage_evidence/kernel_refill_publication_checks.json.zst), [audit receipt](triage_evidence/kernel_refill_publication_audit.json.zst). Decoded capture SHA-256: `29b3379693daa4bbe4d6c0d82f3e1ead4f58edb2eeb5ff123ea1de50d81da73f` (526898 B). Decoded audit SHA-256: `3d217a84d328af55b8532bd150d01c401e23ab529894b8031037f2e8d6c8150a` (17986356 B).

## Continuous selected refill path

The cut starts at0xfffffe000bd72b40 with an explicitly declared mid-refill frame. It does not execute the refill entry/prologue or prove earlier admission. X19 denotes fixed slot2, X24=0 old physical pages, u16[zone+0x38]=N in{1,2,3}; the page-object allocator returns N declared64 B objects. Source stores prepend each returned object to the list, extracts its PFN, and calls the original zero wrapper with physical byte address PFN32<<14 and length16384 B. Both the in-interval64 B object-stride conversion and the out-of-interval u32[object+0x3c] route execute in separate cases. [RP2]

Cache attributes are explicitly returned as0 for these new cuts, selecting original `_memset` through the zero wrapper. All N16 KiB declared aliases begin nonzero and become zero through original store instructions. The [physical-zero report](kernel_physical_zero_report.md) separately covers other attribute values and its logical64 B DC ZVA model. No DC ZVA operation is needed or executed in this increment's private cuts. Native cache attributes/configuration remain unknown. [RP2,RP7]

The source passes the newest object as X4 to the original list consumer at0xfffffe000bd72a8c. The consumer saves `[object]` as next, clears that link, updates the observed page-object flags, then invokes the per-page adapter for virtual offsets0,16384,... . Thus zero requests occur in acquisition order while mapping requests consume PFNs in reverse object order. The receipt stores18 exact earlier-zero/later-mapping request links;17 are first requests for acquired pages, and one is the value-6 retry request for the same page. These links establish request provenance and ordering, without asserting native mappings. [RP2]

| Boundary | Exact selected caller-side ABI |
| --- | --- |
| Page acquisition0xfffffe000be100ec | W0=2; declared returned64 B object |
| Refill call0xfffffe000bd72a8c ->0xfffffe000bdc12cc | X0=0xfffffe000cb81140; X1/X2=virtual base+old byte extent; X3=new byte extent; X4=LIFO head; W5=combined flags; W6=12; W7=mode; one stack byte |
| Consumer ->0xfffffe000bdc15a8 | X0=object/map context; X1=virtual base; X2=page offset; X3=current page object; X4=mode; W5=derived options; X6=tag |
| Adapter ->0xfffffe000be5b2e8 | X0=0xfffffe000cb0bf18; X1=base+offset; X2=PFN32<<14; W3=mode or mode&~4 under context-byte bit0; W4=0; X5=options; W6=1; X7=derived attribute; ninth stack byte=low8(tag) |
| Refill call0xfffffe000bd72adc ->0xfffffe000bd73b5c | X0=zone; X1=virtual base; W2=0; X3=old pages; W4=low32(old+new pages); W5=0 initial used quantity |

In the private primary fixtures, the consumer receives flags0x200, W7=3 and tag0x23; the first lower request uses W3=3, W4=0, X5=0, W6=1 and X7=1. A returned value6 triggers an unlock, recomputation and second request with X7 masked by0x18, giving0 here, followed by a source lock tail call when the retry returns a non6 value. A raw return5 also follows the non6 return path in its separate control. The native result-code names and success interpretation are unknown; neither0 nor5 is treated as independently established mapping success. List/page/lock leaves and lower results are explicit no-RAM return models. [RP2,RP7]

## Per-CPU geometry and ready publication

The original constructor's request-bit24 path ORs0x40 into u32[zone+0x3c] at0xfffffe000bd775ec/0xfffffe000bd775f0. Its per-CPU geometry takes the numbering count at0xfffffe0007e66f38 and computes low32(count<<14) bytes. The earlier fixed slot2 request carries bit24; the [permanent-storage report](kernel_permanent_storage_report.md) separately establishes its setup callback's flag0x100 and extent1. New main fixtures retain the relevant0x100|0x40 bits, extent1 and declared N/count geometry. This is a minimal source-compatible entry state, not a reconstruction of every flag or completed fixed-zone construction. [RP3,RP7]

At fresh metadata insertion, flag0x100 bypasses generic bitmap creation and routes the page to the ready queue even when used=0. Flag0x40 makes the logical page quantity1; otherwise it is the total physical-page quantity. The raw capacity calculation is unsigned `((low16(logical_pages)<<14)-tail) mod2^32 / element_extent`, with A64 UDIV returning0 for a zero divisor. For these extent1/tail0 fixtures, capacities are byte quantities. [RP3]

| Entry flags | Physical pages N | Logical pages | Capacity added at zone+0xa8/+0xac | zone+0x8c/peak | Head / child metadata class in fixtures |
| --- | ---: | ---: | ---: | ---: | --- |
| 0x140 | 1,2,3 | 1 | 16384 B each | 1 | Head0x1402; child0xf402 |
| 0x100 control | 3 | 3 | 49152 B each | 3 | Head0x3402; child0xe402 |

The0x400 bit in those headers is an explicit inherited fixture bit; low zone ID2 is source-derived. Original stores initialize u16 used=0, u32 cursor=0 and link storage=0 before queue insertion. Child records encode their page index in byte+2 and remaining physical-page count in byte+3. Ready insertion publishes index `(metadata-translation_base)>>4` at zone+0x9c, encodes the positive head address in metadata+12 and retains/updates list links. The finite fresh-queue cases begin with no old head; they do not prove all preexisting queue topologies. The local head-push contracts additionally cover an arbitrary stored old head. [RP3]

The source index published in the fixtures is0xf8001f40. The original allocator's signed32 interpretation constructs declared PAGE=0xfffffe0007d00000 from that index. Physical count N, logical allocation capacity and per-CPU storage stride are distinct: the main N-page records retain only16384 logical bytes available for allocation, while CPU storage slots are16384 B apart. [RP3,RP5]

## Accounting and consumer epochs

Routine0xfffffe000bd01454 is an accounting helper, not the page-list mapping boundary. Its direct path uses low16(W1) as an offset into X0, atomically adds X2 to the u64 at base+offset+8, and computes the resulting total. Other captured branches contain per-CPU aggregation/threshold machinery, whose complete policy semantics remain unknown. In the selected refill path, the original helper receives a declared ledger, W1=0x10 and X2=N, advancing its counter97 ->97+N. The refill also increments the selected CPU's separate counter by N, and metadata insertion increments the global physical-page total123 ->123+N. Those counts remain physical pages even for per-CPU logical capacity1. [RP4]

After the cut publishes ready metadata, exact final private RAM and recorded regions transfer to the original magazine-zone creation/publication component. A further declared new-call epoch transfers that output to the complete original cache initializer. Original permanent allocation executes inside both consumers; its cursor advances0 ->32 ->128 and used advances0 ->32 ->96. Statistics return PAGE, cache return PAGE+64, and the32 B alignment gap remains zero. The initialization leaves u16 counts at cache+4/+6 untouched; they now retain source-produced zeros, rather than the preceding report's deliberate nonzero-backing controls. [RP5]

| Physical pages / numbering count | Current CPU | Magazine capacity | Source statistics return | Source cache return | Publication / cache visits |
| ---: | ---: | ---: | --- | --- | ---: |
| 1 | 0 | 8 | 0xfffffe0007d00000 | 0xfffffe0007d00040 | 246 /133 |
| 2 | 1 | 10 | 0xfffffe0007d00000 | 0xfffffe0007d00040 | 246 /153 |
| 3 | 2 | 14 | 0xfffffe0007d00000 | 0xfffffe0007d00040 | 233 /173 |

Every checked CPU slot has both magazine counts0, source-written current/spare pointers, control fields and list links. Typed magazine storage remains an explicit zero-storage leaf model; only the permanent statistics/cache storage provenance is newly extended. The prospective virtual storage and physical-clear aliases are declared private fixtures. Lower mapping calls have no native effects in the model, so their matching PFNs do not establish real physical/virtual alias ownership. Exact new-call state transfer does not prove native epoch continuity, synchronization or successful startup. [RP5,RP7]

## Verification and bounds

Eighteen nonvacuous new source queries are UNSAT over97 distinct PCs/instruction instances and79 linked-edge obligations. They cover the refill's list/mapping and insertion ABIs, destructive list pop, common PFN expression, lower nine-argument request, permanent bitmap/queue gates, fresh header and disjoint payload preservation, ready-head encoding/publication, two independent u32 accounting lanes, direct ledger atomic update, constructor per-CPU flag/span, and logical capacity conversion/division. Ten previous physical-zero source queries and two byte-separation lemmas are rechecked. The proofs are local block contracts, rather than universal full-refill or arbitrary queue-topology proofs. [RP6]

Fifteen components pass129 independent semantic checks: nine continuous refill cuts and three creator/cache pairs. The first six cuts cross N in{1,2,3} with both PFN extraction routes under per-CPU flags; additional cuts exercise return6 retry, raw return5 continuation and the three-page flag0x40-clear capacity control. Source entry is always the declared mid-refill frame; the cut ends immediately after the original metadata inserter returns. Complete original acquisition/list/pmap/lock implementations remain modeled. [RP6,RP7]

Fresh independent replay checks37461 original visits across845 of3720 captured PCs,36177 ordinary writes/287850 B,1659 reads/10639 B,15 final boundaries,15728640 whole-private-RAM bytes and751500 final recorded-region bytes. It reconstructs61 original publication entries,17 clear entries and12 permanent entry/return events, and checks183 explicit leaf model contracts. The180 source PAC steps and3 creator PACDA envelopes remain logical treatments. No DC effect is substituted in these new executions. [RP6]

Three source-NOP controls are rejected independently: lower physical-address construction at0xfffffe000bdc1670 fails the exact mapping-request oracle; ready-head store0xfffffe000bd7446c fails metadata/guarded-state comparison; accounting atomic update0xfffffe000bd01488 fails exact counter comparison. Nonzero payloads and untouched trailing pages/record guards distinguish actual clears from pre-zeroed fixtures. The receipt records every source visit/read/write, exact entry/boundary state, final private storage, zero-to-request correspondence, declared epoch links, unexecuted PCs and rejected controls. [RP6]

Extraction is O(K+I+F) time/space for the pinned collection/fixup storage K, captured instruction bytes I and retained fixups F, with a fixed image segment layout. Source-formula construction is O(I+Q) in visited instructions and formula DAG Q; SMT search has no asserted polynomial bound and is limited to30 s/query. Execution, independent byte oracles and replay are O(V+J+R) time/space in visits V, journal bytes J and mapped/checked RAM R. Native acquisition, mapping, helper progress and whole-refill complexity remain unknown. [RP6,RP7]

The capture/audit JSON archives use `zstd --ultra -22 -q -T1`; each is roundtrip verified before removing raw JSON. Delivery reconstructs fresh extraction, source proofs and private executions, compares canonical SMT expressions, checks the exact owned publication delta and original inputs, and scans decoded archives/nested RAM for analyst-local paths. [RP6]

## Assumption register and falsification probes

| Assumption | Used by | Stress test / falsification probe |
| --- | --- | --- |
| RP-A1: Pinned original images, compiler intervals and logical pointer decoding identify this build | RP1-RP7 | Rehash originals, reconstruct eleven captures and compare seven complete prior functions; no cross-build/native inference |
| RP-A2: Selected entry frame, zero old count, N/count/extent geometry and minimal relevant flags are declared | RP2-RP6 | Check exact initial/final RAM, both PFN routes, three N values, constructor bit24 proofs and flag0x40-clear control; recover full earlier refill admission separately |
| RP-A3: Acquisition, clear-alias, lower mapping and list/lock leaves obey explicit private no-RAM contracts | RP2,RP4-RP7 | Reconstruct all183 model arguments/results, ninth stack byte and retry order; source mutations reject wrong PA/counters; actual lower bodies/native ownership remain open |
| RP-A4: Private ARM64 CPU, ordinary ABI and logical PAC treatments qualify instruction replay only | RP2,RP4-RP7 | Fresh independent CPU, original bytes, all journals/frame state and logical envelopes; no hardware authentication or synchronization claim |
| RP-A5: Declared metadata/zone/payload regions are disjoint and the selected ready queue starts empty | RP3-RP6 | Arbitrary disjoint payload-byte source proof, complete guarded-state oracles, source head-store mutation and separation rechecks; existing-list/native exclusion requires separate evidence |
| RP-A6: Exact predecessor state may feed a separately declared creator/cache call epoch | RP5-RP7 | Replay both transfers, source allocation entry/returns, metadata/statistics changes and zero counts in all CPU slots; native epoch/owner continuity remains unknown |
| RP-A7: Finite components, source-local proofs and request provenance support only the reported conditional scope | RP6,RP7 | Record unexecuted PCs, retry/raw-return controls, ordinary/per-CPU capacity split and three negative controls; do not infer native lower success or full boot from non6 returns |

## Bounded continuation and quality gates

| Impact | Next discriminating work | Result it could establish |
| --- | --- | --- |
| High | Recover lower mapping leaf0xfffffe000be5b2e8 and its actual page-table/attribute effects | Conditional/native PA-to-VA identity and the meaning of return6/other values |
| High | Recover acquisition leaf0xfffffe000be100ec and full earlier refill admission/reservation path | Origin, ownership, lifetime and feasibility of the objects/virtual spans now joined |
| Medium | Execute original fixed slot2 creation and actual geometry/flag production | Replace minimal0x140/extent1/N entry fixtures with earlier source-produced state |
| Medium | Classify alternate refill, old-page extension, list consistency and scheduler/lock paths | Generalize beyond the selected fresh queue and explicit no-RAM leaves |
| Low | Tie the proven storage path to a native daemon-kext buffer/selector/right/transaction record | Transport attribution beyond internal kernel allocation context |

This increment establishes no additional incoming/outgoing Mach endpoint, right disposition, message ID or emission site. All new boundaries are internal kernel calls, modeled lower returns or explicitly declared new-call epochs. Complete native refill, physical aliases, mapping success, ownership, synchronization, boot completion and same-transaction daemon/kext identity remain unknown. The full research goal remains active. [RP7]

**QG1**: No normative premise is required. **QG2**: Seven assumptions carry claim dependencies and falsification probes. **QG3**: Routine roles, data/control flow, environmental inputs, lower architectural ABIs and Mach-scope limits are covered. **QG4**: Byte/page units, bit widths, modular arithmetic, division, per-CPU versus physical capacity and reproducible algorithmic bounds are explicit. **QG5**: Selected modeled zero backing and the earlier nonzero controls have different declared premises; per-CPU capacity is separated from physical count; native lower results remain unknown. **QG6**: Pinned original bytes, exact nlist limits, source proofs, byte oracles and replay establish provenance. **QG7**: Remaining work is bounded and impact-ranked. All seven gates pass within this scope.
