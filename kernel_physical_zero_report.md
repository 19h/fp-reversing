# Physical zeroing below permanent storage

Subsequent evidence: The [refill-publication report](kernel_refill_publication_report.md) joins a selected original zeroing/list/mapping-request/metadata cut to original statistics/cache consumers under explicit private alias and new-call premises. The per-CPU bit0x40 yields one16 KiB logical capacity across N physical pages. Native mapping effects, ownership and whole-refill execution remain unknown.

The original permanent-storage refill contains an explicit physical-page zeroing request: at `0xfffffe000bd72c40` it calls `0xfffffe000be7b5b8` with X0=zero_extend(PFN32)<<14 and W1=16384 B. The complete 255-instruction callee selects a direct alias or a per-CPU temporary window, then invokes original `_bzero`/`_memset` or generates a full-page `DC ZVA` loop. This establishes a concrete zeroing producer candidate below the [ready-page allocator](kernel_permanent_storage_report.md). It does not establish that a particular native statistics/cache allocation receives those exact physical bytes. [PZ1-PZ6]

```text
original ready allocator -> original refill [whole refill not executed]
  selected page-object route
    page object -> PFN32 -> physical byte address, length16384
      zero wrapper
        +-> inside unsigned direct interval -> declared direct alias
        +-> outside interval -> CPU temporary window index0..3
              |
              +-> selected attribute + full page -> inline DC ZVA
              +-> selected attribute + partial   -> original bzero
              +-> other attribute                -> original memset(...,0,n)
        temporary window: unmap -> nesting decrement -> optional deferred call

[native PFN/alias ownership and refill-to-return identity remain unknown]
```

## Provenance and claims

Primary evidence is the original kernel collection, SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, its compiler function intervals, instruction bytes and nlist records. The preserved normalized kext SHA-256 is `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. No external source, new IDA access or database modification was needed. The reference data sufficed. Descriptive routine roles below are distinct from the three exact symbol identities. [PZ1]

| Captured complete interval, end exclusive | Instructions | Bytes | Role |
| --- | ---: | ---: | --- |
| 0xfffffe000bd71a20..0xfffffe000bd71c10 | 124 | 496 | Ready permanent allocator; exact preceding-capture match |
| 0xfffffe000bd71c10..0xfffffe000bd73084 | 1309 | 5236 | Refill; static capture, selected request block proved |
| 0xfffffe000bd73598..0xfffffe000bd73724 | 99 | 396 | Metadata translation backing helper; static capture |
| 0xfffffe000be7b5b8..0xfffffe000be7b9b4 | 255 | 1020 | Physical-range zero wrapper; private executions |
| 0xfffffe000c6480c0..0xfffffe000c648170 | 44 | 176 | Original bzero; private executions |
| 0xfffffe000c648170..0xfffffe000c648218 | 42 | 168 | Original memset; private executions |
| Total | 1873 | 7492 | Nine selected blocks, 41 instructions |

| Exact address | Original nlist name(s) | Entry / n_type / n_section |
| --- | --- | --- |
| 0xfffffe000be67808 | `_pmap_cache_attributes` | com.apple.kernel /15 /18 |
| 0xfffffe000c6480c0 | `___bzero`, `_bzero` | com.apple.kernel /15 /19 |
| 0xfffffe000c648170 | `_memset` | com.apple.kernel /15 /19 |

No exact nlist name is recovered for the wrapper, refill, metadata helper, direct-alias helper, window map/unmap helpers or deferred helper. Naming the latter helpers describes their caller-side use; their complete implementation contracts remain unknown. The immediate B/BL inventory rehashes725 executable spans and scans15490987 aligned words, finding28 direct branch sites to the wrapper, all in com.apple.kernel. This includes the refill call above; indirect/data references, other encodings and feasibility at every caller are outside the scan. [PZ1]

| Claim | Established result | Dependencies |
| --- | --- | --- |
| PZ1 | Original bytes, complete intervals, exact symbol identities and bounded branch census | PZ-A1, PZ-A2 |
| PZ2 | Selected refill page-object/PFN request and distinct metadata-backing address calculation | PZ-A1, PZ-A3 |
| PZ3 | Wrapper range, attribute, chunk, alias and original clear-call contracts | PZ-A1, PZ-A3, PZ-A4 |
| PZ4 | Four-iteration inline address coverage under the64 B logical DC premise | PZ-A1, PZ-A3-PZ-A5 |
| PZ5 | Byte oracles, full private replay, nonzero guards and rejected source mutations | PZ-A1-PZ-A6 |
| PZ6 | Native ownership, refill integration, environmental and IPC limits | PZ-A1-PZ-A6 |

Artifacts: [capture generator](triage_evidence/recover_kernel_physical_zero.py), [private executor and oracle](triage_evidence/probe_kernel_physical_zero.py), [independent replay](triage_evidence/replay_kernel_physical_zero.py), [source audit](triage_evidence/audit_kernel_physical_zero.py), [delivery verifier](triage_evidence/verify_kernel_physical_zero_delivery.py), [source capture](triage_evidence/kernel_physical_zero_checks.json.zst), [audit receipt](triage_evidence/kernel_physical_zero_audit.json.zst). Decoded capture SHA-256: `b834c970a2369dab217e58a9fd0f362705734eb64649a75e4b0bfe5cf9061b0e` (506481 B). Decoded audit SHA-256: `17138aec0731058064e32bbd1f3a22064e0bad62b384e393e9fa0c8920a1da33` (18236220 B).

## Refill edge and metadata distinction

The selected refill loop calls `0xfffffe000be100ec` at `0xfffffe000bd72b84` with W0=2 and branches on a null return. Its returned object's native type is unknown; the caller links the prior object through its first u64. It compares the object against lower=u64[0xfffffe0007ef8e80] and upper=u64[0xfffffe0007ef8e78]. Inside the unsigned half-open interval it computes the PFN from a64 B record stride; outside it loads PFN32 from object+0x3c. [PZ2]

| Route / site | Exact expression or request |
| --- | --- |
| Object in interval, 0xfffffe000bd72c20..0xfffffe000bd72c30 | PFN32=(low32((object-lower)>>6)+u32[0xfffffe0007ef8000]) mod2^32 |
| Object outside interval, 0xfffffe000bd72bb0 | PFN32=u32[object+0x3c] |
| 0xfffffe000bd72c38 | X0=zero_extend_64(PFN32)<<14, a byte address |
| 0xfffffe000bd72c3c | W1=0x4000=16384 B=16 KiB |
| 0xfffffe000bd72c40 | BL to zero wrapper0xfffffe000be7b5b8 |

The formal request proof starts at the in-interval computation with explicitly declared object/lower/PFN inputs. It does not prove the earlier allocator's return, range membership, loop feasibility, page ownership or completion of the1309-instruction refill. The out-of-interval load is source-classified, rather than separately executed. [PZ2,PZ6]

The99-instruction helper0xfffffe000bd73598 services metadata translation addresses. For inputs X0=A, X1=N, it forms metadata=u64[0xfffffe0007e66f00]+((A>>10)&0xffffffff0), starts at metadata&~0x3fff and derives an end from metadata+((N>>14)<<4). Its loop checks/populates16 KiB metadata pages through0xfffffe000bc9cee8,0xfffffe000be67cac and0xfffffe000bdc1f18, with atomic-lock and retry paths. Population requests use length16384, W2=0x182, W3=1. This is a separate metadata-backing interface; neither that source role nor a population request proves zeroed permanent payload backing. Mapping/helper internals and native progress remain unknown. [PZ2,PZ6]

## Wrapper ABI, mapping and environmental state

At entry X0=physical byte address P, X1=remaining byte length N. N=0 returns through the original frame without cache/mapping calls. The wrapper uses a14-bit page offset and PFN=P>>14. Comparisons and lengths are unsigned; register arithmetic is modulo2^64 unless a narrower width is explicit. Valid readable mapping extents and positive progress are separate premises. [PZ3]

| State or call | Caller-side contract |
| --- | --- |
| u64[0xfffffe0007ef81e0], u64[0xfffffe0007ef81e8] | Direct interval [lower,upper); outside iff P<lower or P>=upper |
| BL0xfffffe000be67808 | `_pmap_cache_attributes(P>>14)`; return retained in X22 |
| Inside interval, BL0xfffffe000be76154 | X0=P, X1=&stack_chunk; returned X0 is alias; helper may alter available length |
| Outside interval, TPIDR_EL1+0x1c8 | u32 nesting increments before window mapping |
| TPIDR_EL1+0x1b8 | u16 current CPU index |
| Outside interval, BL0xfffffe000be69d4c | X0=PFN, W1=3, X2=attributes; W0 window index must be<4 unsigned |
| Window alias | 0xfffffecfffd00000+(CPU16<<16)+(index<<14)+(P&0x3fff) |
| Chunk | min_unsigned(available,remaining); saved at current SP+0x28 |
| Window available | 16384-(P&0x3fff) |
| Direct available | Initially remaining; direct helper can replace it; fixture model leaves it unchanged |
| After a chunk | P+=chunk, remaining-=chunk; next page offset explicitly0 |

The private direct-helper model returns a declared contiguous alias without RAM effects. Direct cases remain within one source16 KiB physical page. Window cases use CPU2 and indices0,1,2 with separately declared virtual storage; these aliases are not backed by demonstrated native physical pages. The source index>=4 path constructs the original diagnostic and stops before0xfffffe000c62a2b0; no diagnostic implementation or guaranteed nonreturn is assumed. [PZ3,PZ5,PZ6]

For a window, BL0xfffffe000be6a0e0 receives the same index after clearing. The wrapper reloads the nesting counter, routes zero-before-decrement to0xfffffe000c63aec8, decrements/stores it, and if it becomes zero reads u64[TPIDR_EL1+0x1c0], then bit2 of the referenced byte+0x4c. A set bit calls0xfffffe000be8663c before range progress. The source is consistent with temporary preemption nesting/deferred work, but the native scheduler contract and exclusion guarantee are unknown. Those two callees are explicit no-RAM models in private cases. No IRQ/hardware ordering or concurrent visibility is established. [PZ3,PZ6]

## Clear selection and exact page-loop coverage

Only low8(attributes) enters dispatch. Values>22 select memset. Values<=22 test `(1<<value)&0x00440844`, selecting exactly{2,6,11,18,22}; the mask encodes no recovered human-readable cache-mode names. [PZ3]

| Attribute membership | Chunk length | Original action |
| --- | --- | --- |
| In{2,6,11,18,22} | 16384 B | Inline DC ZVA loop |
| In{2,6,11,18,22} | Any other admitted chunk | `_bzero(alias,chunk)` at0xfffffe000be7b91c |
| Other low8 value | Any admitted chunk | `_memset(alias,0,chunk)` at0xfffffe000be7b95c |

The inline loop initializes an offset to-256 and advances it by4096 across four iterations. Each iteration generates64 DC ZVA addresses at64 B spacing. Under the aligned16 KiB alias premise, the source-derived address proof establishes all256 addresses equal alias+64*j for j=0..255, and the final branch leaves the loop. Dimensional check:4*64*64 B=16384 B. [PZ4]

The explicit logical DC model zeros the operand-containing aligned64 B block in private storage. This is a declared architectural-effect premise, not observed hardware behavior or evidence of the target's DCZID_EL0/cache configuration. The address proof plus that premise covers one page; it is not a universal native translation or cache-coherency proof. `_bzero` also uses DC ZVA for long sizes, while `_memset` uses original scalar/pair stores in this capture. Those source functions execute within the components; they are not replaced by clear-return models. [PZ4-PZ6]

## Verification

Ten nonvacuous source queries are UNSAT, covering181 distinct PCs,589 instruction instances and579 linked-edge obligations. They establish the selected refill request, unsigned direct interval/PFN call, window-alias fields, saved unsigned minimum, low8 dispatch limit, five-value mask, full-page gate, both original clear ABIs, and four unrolled inline-loop address iterations. Two prior byte-separation lemmas are rechecked. Formal coverage is local; it does not establish the full refill or whole native zero-wrapper contract. [PZ5]

Eighty components pass425 independent semantic checks:44 wrapper cases,18 bzero cases and18 memset cases. They include lengths0,1,7,8,9,15,16,17,63,64,65,127,128,129,255,256,4096 and16384 B across the respective sets, nonzero guarded payloads, every low attribute0..23, high attribute0x10002, unaligned starts, nested/deferred controls, invalid window index4, and three-chunk clears of16483 B starting at page offset16380. The latter split4+16384+95 B. Native caller admission is not inferred. Memset controls additionally check low-byte truncation of0x12345 to0x45 and original destination return. [PZ5]

Fresh independent replay imports no new executor/audit. It checks16254 original source visits across337 of1873 captured PCs,10268 ordinary writes/81361 B,899 reads/7021 B,80 boundaries,83886080 whole-private-RAM bytes,393920 final recorded-region bytes,79 original clear entries and107 declared model contracts. It separately reconstructs1157 logical DC operations/74048 B. Two hundred forty-five source PAC steps remain logical. Three changed-source controls replace the inline DC at0xfffffe000be7b708, bzero byte store at0xfffffe000c64814c, or memset byte store at0xfffffe000c648200 with NOP; each fails the independent whole-payload/guard oracle. [PZ5]

The audit stores all unexecuted PCs, exact journals, logical DC effects, initial/final private storage, proofs and rejected controls. Ordinary-memory journal totals exclude logical DC effects; reported whole-RAM totals include the explicit private DC writes. A single finite component's success does not prove all lengths, native termination, arbitrary mappings or concurrent effects. [PZ5,PZ6]

Extraction uses O(K+W+I+F) time and space for collection/fixup bytes K, scanned words W, captured instructions I and retained fixups F; the word inventory is a single linear pass. Private execution, oracle construction and replay cost O(V+J+R) time/space for visits V, journal bytes J and mapped/checked RAM R. The inline address certificate unrolls exactly four source iterations; no general SMT complexity bound is asserted beyond the30 s per-query limit. Native helper progress and whole-refill complexity are unknown.

Capture and audit JSON are compressed with `zstd --ultra -22 -q -T1`, roundtrip verified and published only as archives. Delivery reconstructs extraction/proofs/components, compares canonical SMT expressions, verifies exact publication delta and original-input custody, and scans decoded archives including nested RAM for analyst-local paths. [PZ5]

## Assumption register and falsification probes

| Assumption | Used by | Stress test / falsification probe |
| --- | --- | --- |
| PZ-A1: Pinned KC bytes, function starts and logical pointers correspond to this build | PZ1-PZ6 | Rehash original collection; reconstruct complete function captures and compare prior allocator bytes |
| PZ-A2: Immediate aligned B/BL scan scope is sufficient for the stated direct census | PZ1 | Rehash725 spans and decode15490987 words; indirect/data references remain explicitly excluded |
| PZ-A3: Local source-block entry values/storage and modulo-width semantics are declared | PZ2-PZ5 | SAT premise checks, UNSAT counterexamples and exact byte re-extraction; raw out-of-domain native validity remains unknown |
| PZ-A4: Cache/mapping/deferred leaves obey declared no-RAM return contracts in private fixtures | PZ3-PZ5 | Reconstruct every model's source PC, arguments, result and call order; recover actual helper bodies for native linkage |
| PZ-A5: Logical DC ZVA granule is64 B and aliases cover declared storage | PZ4,PZ5 | Prove all256 page addresses; reject missing DC control; verify actual target DC configuration/translation before native claims |
| PZ-A6: Private CPU/PAC/frame and disjoint fixture model are sufficient only for finite component claims | PZ5,PZ6 | Independent CPU/journal/full-RAM replay, nonzero guards, invalid-index control and two store-NOP controls; no hardware/native execution inferred |

## Bounded continuation and quality gates

| Impact | Next discriminating work | What it could establish |
| --- | --- | --- |
| High | Join selected zeroed PFNs through actual refill mapping/metadata insertion0xfffffe000bd73b5c to the ready record and signed-index return | Whether zeroed backing reaches the32/64 B statistics/cache consumers |
| High | Recover direct-alias and window map/unmap helpers with original translation state | Native physical/virtual identity, available-length contract and window reuse boundaries |
| Medium | Classify other refill routes and metadata-population retry/lock effects | Whether all successful permanent backing routes share zero initialization |
| Medium | Establish native DC granule, mapping attributes and scheduler/exclusion epoch | Hardware and concurrency conditions omitted by private proofs |
| Low | Expand beyond28 immediate callers to indirect references | Additional consumers without conflating them with Mach transport |

No additional incoming/outgoing Mach endpoint, right disposition, message ID or emission site is established. All new edges are internal kernel calls or declared private mapping boundaries. Native daemon/kext buffer-selector-right-transaction identity, complete boot/refill, lifetime and ownership remain unknown. The research goal remains active. [PZ6]

**QG1**: No normative premise is required. **QG2**: Six explicit assumptions carry falsification probes and claim dependencies. **QG3**: Routine roles, data/control flow, environmental interfaces and Mach-scope implications are recorded. **QG4**: Byte lengths, page/object strides, widths, masks, modulo arithmetic, exact counts and algorithmic bounds are explicit; source SMT search is limited to30 s/query. **QG5**: Ready-path preservation and an explicit selected refill zero call coexist; native allocation-to-zero identity remains an open claim, not a contradiction. **QG6**: Claims cite pinned original bytes, exact nlist records and reproducible receipts. **QG7**: Continuation is bounded and impact-ranked. All seven gates pass within this declared scope.


## pmap and SPTM transport evidence

The lower mapping gateway independently identifies the reserved temporary range [0xfffffecfffd00000,0xfffffecfffe00000) through original CPUWINDOWS diagnostics. Its kernel-context admission rejects this1048576 B interval. This connects the temporary-window environment to the deeper pmap/SPTM boundary while leaving actual physical aliases, mapping effects and ownership unknown. See the [mapping transport report](kernel_mapping_transport_report.md).
