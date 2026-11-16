# pmap context and CPU result-pointer initialization

Original source now connects the mapping gateway's context to an ARM initialization call and connects its CPU result-pointer slot to a separate CPU initializer. The context initializer publishes the root pair, bounds, original geometry object and allocation state. The CPU initializer uses two additional SPTM wrappers, selectors0x13 and0x32, and stores the latter's raw return in the slot consumed by the mapping backend. The wrappers' receiver-side behavior, actual result-record production and native ownership remain unknown. Seven private five-component chains transfer exact state from producers into the earlier admission/backend consumers; these are declared call epochs. [MC1-MC7]

```text
declared boot-root/range-table inputs
  original ARM root cut -> original PA-to-VA converter -> root pair
    original ARM call -> complete context initializer
      root pair + bounds literal + original geometry
      bump/bitmap allocation -> original bzero + logical DC ZVA
      count/queue/policy/ready-state publication
        exact RAM/global transfer into a new declared CPU call
          original VA-to-PA converter, five calls
          wrapper selector0x13 -> declared full identifier
          original PA-to-VA converter -> CPU shared alias
          wrapper selector0x32 -> declared result pointer
          original STR -> CPU block[0]
            exact state transfer -> original admission/descriptor cut
              source-produced descriptor -> declared backend call
                selector2 request -> declared raw status
                CPU block[0] -> two record-word copies when status < 2
```

The primary source is the same pinned original collection, SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. The preserved normalized kext SHA-256 remains `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Compiler function starts, original bytes, two chained pointer fixups, data literals, original diagnostics and nlist records supply provenance. No external build, current source-tree analogue or inferred instruction name substitutes for these bytes. The reference data sufficed; this increment did not use or mutate an IDB. [MC1]

| Claim | Established result | Dependencies |
| --- | --- | --- |
| MC1 | Complete captures, original literals/fixups and bounded initializer callers | MC-A1 |
| MC2 | ARM root pair and complete context initializer publications | MC-A1-MC-A3 |
| MC3 | Original conversion-table ABI and selected conversion paths | MC-A1,MC-A3,MC-A4 |
| MC4 | CPU physical fields, three identifier widths and result-pointer store | MC-A1,MC-A3-MC-A5 |
| MC5 | Exact producer-state joins into earlier admission/backend consumers | MC-A1-MC-A6 |
| MC6 | Nonvacuous source proofs, independent byte oracles/replay and controls | MC-A1-MC-A7 |
| MC7 | External-control/Mach boundaries and bounded continuation | MC-A1-MC-A7 |

Artifacts: [extractor](triage_evidence/recover_kernel_mapping_context.py), [private executor and independent field oracles](triage_evidence/probe_kernel_mapping_context.py), [independent replay](triage_evidence/replay_kernel_mapping_context.py), [source audit](triage_evidence/audit_kernel_mapping_context.py), [delivery verifier](triage_evidence/verify_kernel_mapping_context_delivery.py), [source capture](triage_evidence/kernel_mapping_context_checks.json.zst), [audit receipt](triage_evidence/kernel_mapping_context_audit.json.zst). Decoded capture:534976 B, SHA-256 `f781001a80ec324375b7a2b2b083a98cc7db484f4b6795db264f7977dd6caba2`. Decoded audit:17999078 B, SHA-256 `2115d8cd2fb82edc3a7466a41a2d35c40728c5089399c5deed63f693ddbc9a03`. [MC6]

## Source custody and identification

| Complete interval, end exclusive | Words | Bytes | Role and evidence boundary |
| --- | ---: | ---: | --- |
| 0xfffffe000be7400c..0xfffffe000be75924 | 1606 | 6424 | Earlier ARM/SPTM initializer; two source cuts execute here |
| 0xfffffe000be608f4..0xfffffe000be60d40 | 275 | 1100 | Complete pmap context/bootstrap initialization; original pmap/pmap_bootstrap diagnostics |
| 0xfffffe000be734f0..0xfffffe000be73684 | 101 | 404 | Complete CPU initialization; original kvtophys_nofail diagnostic |
| 0xfffffe000c6201c0..0xfffffe000c62026c | 43 | 172 | Original PA-to-VA converter |
| 0xfffffe000c64529c..0xfffffe000c645674 | 246 | 984 | Original VA-to-PA converter; selected table/disabled paths execute |
| 0xfffffe000c6211d0..0xfffffe000c62120c | 15 | 60 | SPTM selector0x13 wrapper; raw return modeled at entry |
| 0xfffffe000c62120c..0xfffffe000c621248 | 15 | 60 | SPTM selector0x32 wrapper; raw return modeled at entry |
| 0xfffffe000c6480c0..0xfffffe000c648170 | 44 | 176 | Exact nlist aliases ___bzero and _bzero; original body executes |
| Seven retained gateway/descriptor/backend/category/pre/post/validation functions | 1481 | 5924 | Byte-identical to retained mapping captures |
| Total, fifteen functions | 3826 | 15304 | Nine complete functions match earlier captures; four undecoded words preserved |

Only the two bzero aliases have exact nlist names among these fifteen function starts. The diagnostic identifiers justify descriptive roles, rather than exact exported function names for the other starts. Scanning2558561 aligned4 B words in the original __TEXT_EXEC, __TEXT_BOOT_EXEC and __KLD segments finds two BL-immediate references to the two initializers:0xfffffe000be75458 ->0xfffffe000be608f4 within ARM function0xfffffe000be7400c, and0xfffffe000be78164 ->0xfffffe000be734f0 within compiler function0xfffffe000be780f8. The latter caller is located, not captured or executed here. Indirect/tail/other-fileset callers and native startup reachability remain open. [MC1]

## ARM root pair and context publication

The original ARM cut at0xfffffe000be74108 reads the raw boot root from global0xfffffe0007e6d838, copies it to0xfffffe0007e6daa8, and calls the original PA-to-VA converter with an output slot at SP+0x48. At0xfffffe000be74134 it stores that output at0xfffffe0007e6dab0 if W0=0, otherwise zero. Thus the pair's first word is the raw physical-root input and its second word is its converted virtual alias. The boot root and conversion-table ownership are declared private inputs, not recovered native values. [MC2,MC3]

The second ARM cut starts at0xfffffe000be75444. Source reads u64[SP+0x30], computes `(input+0x1ffffff) & 0xfffffffffe000000` modulo2^64, and passes that32 MiB rounded value in X0 to the context initializer at0xfffffe000be75458. The selected call returns to0xfffffe000be7545c. The complete context initializer executes between those source locations, including its original prologue/epilogue, conversion calls, bitmap construction and queue stores. Its lock initializer, one initialization leaf, four absent boot-parser queries and failed capability query have explicit no-RAM return models. Their native effects remain unknown. [MC2,MC5]

| Context0xfffffe000cb0bf18 offset | Width | Published value | Original store PC |
| --- | ---: | --- | --- |
| +0x00 | u64 | u64[0xfffffe0007e6dab0], converted root alias | 0xfffffe000be6095c, first STP word |
| +0x08 | u64 | u64[0xfffffe0007e6daa8], raw physical root | 0xfffffe000be6095c, second STP word |
| +0x10 /+0x18 | 2*u64 | 0xffff800000000000 /0xffffffffffffffff from original Q literal | 0xfffffe000be60968 |
| +0x20 | u64 | Original geometry object0xfffffe0007e6cb78 | 0xfffffe000be60944 |
| +0x30 /+0x38 | 2*u64 | Queue-head address0xfffffe000cb0c028 | 0xfffffe000be60a44 |
| +0x40 /+0x48 | 2*u64 | Zero optional-interval pair | 0xfffffe000be6098c |
| +0x60 | u64 | Zero | 0xfffffe000be60990 |
| +0x68 | u32 | 1 | 0xfffffe000be60970 |
| +0x6c /+0x6e | u16 /u8 | Zero /zero | 0xfffffe000be60994 /0xfffffe000be60974 |
| +0x70 | u32 | 0x01010000, low32 of original D literal | 0xfffffe000be60988 |
| +0x74 /+0x75 /+0x76 | 3*u8 | 0 /0 /1 | 0xfffffe000be60948 /0xfffffe000be6097c |

The on-disk context's128 B, root pair's16 B and three selected CPU blocks'49152 B are zero. Source initialization replaces these zero bytes in the private chains. It does not establish that all native users observe one completed initialization epoch. The earlier gateway's bounds are unsigned lower-inclusive/upper-exclusive, so this published upper value excludes VA0xffffffffffffffff. The prior CPUWINDOWS exclusion remains a separate gateway condition. [MC2,MC5]

The geometry object is120 B. Its two chained-fixup targets are row table0xfffffe0007013328 and object0xfffffe0007e6cad8. Source fields include u64[+0x30]=0x0060000000000000, u64[+0x38]=0x0020000000000000, u32[+0x48]=3, u32[+0x4c]=0, u64[+0x58]=0x4000 and u64[+0x60]=0xe. All four56 B rows are retained, rather than inferred from a fixture. [MC1,MC2]

| Row | u64[+0] | u64[+8], alignment mask | u64[+16], shift | u64[+24] | Remaining u64 fields |
| --- | --- | --- | --- | --- | --- |
| 0 | 0x800000000000 | 0x7fffffffffff | 0x2f | 0x800000000000 | 1,2,0 |
| 1 | 0x1000000000 | 0xfffffffff | 0x24 | 0x7ff000000000 | 1,2,0 |
| 2 | 0x2000000 | 0x1ffffff | 0x19 | 0xffe000000 | 1,2,0 |
| 3 | 0x4000 | 0x3fff | 0xe | 0x1ffc000 | 3,2,2 |

Selector3 therefore chooses the original0x3fff alignment mask, requiring16384 B alignment in the admitted gateway path. Original geometry field+0x30 is0x0060000000000000; the earlier transport report used the declared value0x0020000000000000 in its selected fixtures. With PA0x400000, protection3 and descriptor flag1, the original initialized geometry produces descriptor0x0460000000400403 and u16 attributes0xc0. The prior fixture result0x0420000000400403 remains valid for its declared geometry; it is not this initialized object's value. [MC2,MC5]

## Bitmap, allocation and initialization domain

Let N be u32[u64[0xfffffe0007f8b5e0]+0x68], A the old bump pointer at0xfffffe0007e6da98, and all address arithmetic be u64 modulo2^64. Source first publishes N, then computes the following byte quantities. [MC2,MC6]

```text
budget_B = (((N + 63) mod 2^32) >> 3) & 0x1ffffff8
aligned_A = (A + 7) & 0xfffffffffffffff8
partial_A = (aligned_A + budget_B) mod 2^64
rounded_A = (partial_A + 16383) & 0xffffffffffffc000
clear_B = rounded_A - aligned_A
```

The carry diagnostic tests the second add, `partial_A+16383`; the first budget add is unflagged and may wrap independently. These equations do not establish a universal nonwrapping allocation theorem. Selected private inputs make both sums nonwrapping and provide valid conversion-table coverage for the entire clear. Source calls the original PA-to-VA converter twice for aligned_A, publishes its first converted alias at0xfffffe0007e6cf98, and sends the second alias plus clear_B to original bzero. Logical DC ZVA effects use64 B blocks in private RAM; native cache granularity/coherency and physical ownership are unproved. [MC2,MC3,MC6]

Within the successful selected domain, source sets bitmap bits0..N-1, then clears the reserved identifiers0,256,512,... below N. It publishes `N & 0xffffffc0` at0xfffffe0007e6ce44. A zero rounded count reaches the original pmap_bootstrap diagnostic. With an absent `pmap_asid_plru` boot argument, the adjacent policy word is1 iff the rounded count is unsigned-greater-than256. N513 and1024 execute the vector/scalar distinction; N257 rounds down to256 and keeps policy0. Counts1 and63 execute initialization and then the original diagnostic. N=0 is deliberately not executed as a complete initializer: its earlier `N-1` wraps to0xffffffff and enters the bulk bitmap path before the later zero diagnostic. No external reachability or vulnerability follows from this local domain observation. [MC2,MC6,MC7]

The initializer makes the queue head's two words point to the context, publishes its entry argument at0xfffffe000cb0c320, and stores raw constant-0x13000000001 at0xfffffe000cb0c038. Successful cases also set the captured sentinel vectors at0xfffffe000cb89010/0xfffffe000cb89030, the pair{0,0x11} at0xfffffe000cb0c040, capability byte0xfffffe0007e6ce11=0 after the declared failed query, and ready byte0xfffffe0007e6ce10=1. Their full native synchronization/read-side protocol remains unknown. [MC2]

## Original range-conversion ABI

Both converters take X0=input address and X1=&u64 output. Global byte0xfffffe0007f8c718 bit0 gates the interface; global0xfffffe0007f8c720 points to a u32 count, and0xfffffe0007f8c728 points to the range table. Each24 B record contains physical base u64[+0], virtual base u64[+8], page count u32[+16] and a remaining u32[+20] whose role is unknown. A selected record's extent is `zero_extend(page_count)<<14` B. [MC3]

| Routine / path | Original contract | Private coverage limit |
| --- | --- | --- |
| PA-to-VA0xfffffe000c6201c0 | Linear half-open physical-interval search; output=virtual_base+(input-physical_base); zero output rejected; write only on success; raw status0 | Original full body, table-hit paths execute |
| PA-to-VA feature/null/exhausted branches | Raw statuses1/2/4 respectively | Captured; new chains cover enabled hits, not every failure branch |
| VA-to-PA0xfffffe000c64529c table path | Allowed VA interval comes from u64[0xfffffe0007f8c740] and u64[0xfffffe0007f8c748]; selected record gives physical_base+(input-virtual_base) | Original full function captured; table-hit and disabled paths execute |
| VA-to-PA disabled feature | Raw status1, no converted output | CPU failure case reaches original kvtophys_nofail diagnostic |
| VA-to-PA fallback | Additional translation/helper/metadata paths outside the selected table domain | Captured, unexecuted; complete fallback semantics unknown |

The private table has four disjoint rows for root, bitmap, CPU blocks and shared region, using physical bases0x800000/0x900000/0xa00000/0xb00000 and extents1/4/3/6 pages. These are explicit test inputs. Original code performs all73 recorded conversion calls; no address-conversion return model supplies their outputs. Source-proved selected-record arithmetic is conditional on already selecting the record and does not prove native table construction or universal search admissibility. [MC3,MC6]

## CPU initializer, SPTM selectors and consumer join

CPU entry W0 is stored at u32[u64[TPIDR_EL1+0x1c0]+0x8e8]. The CPU block is `0xfffffe000cac8000 + (signed64[thread+0x1b8] ASR16)`. The private encoded thread values select blocks0/1/2 with16384 B stride; this does not establish a universal native thread layout or actual online CPU count. [MC4]

| CPU block field | Original input to converter or wrapper | Publication PC |
| --- | --- | --- |
| +0xe10, u64 | VA-to-PA(block+0x10) | 0xfffffe000be73544 |
| +0xe18, u64 | VA-to-PA(block+0x610) | 0xfffffe000be73564 |
| +0xe20, u64 | VA-to-PA(block+0xc10) | 0xfffffe000be73584 |
| +0xe28, u64 | VA-to-PA(block+0xc10), repeated original request | 0xfffffe000be735a0 |
| +0x1d70, u64 | VA-to-PA(block+0x1310) | 0xfffffe000be735c4 |
| +0x1d78, u16 | Low16 of selector0x13 return | 0xfffffe000be735fc |
| +0x08, u64 | PA-to-VA(u64[0xfffffe0007e6d0b8]+(zero_extend(low32(identifier))<<15)); zero if conversion status nonzero | 0xfffffe000be73628 |
| +0x00, u64 | Full raw selector0x32 return, interpreted by earlier backend as result pointer | 0xfffffe000be73634 |

The first five nonzero conversion statuses converge on the original `kvtophys_nofail` diagnostic. The selector0x13 call at0xfffffe000be735f4 receives X0=u32[topology+136*zero_extend(low32(CPU))+4], where topology=u64[0xfffffe0007ef8c08]; source retains a signed32-offset poison gate. The selector0x32 call at0xfffffe000be73630 receives the complete saved64-bit identifier. Identifier0x123400000001 distinguishes all three widths: the full value reaches the second wrapper, stored u16=1, and shared-region offset32768 B uses low32=1. No high-bit truncation is inferred for the second wrapper. [MC4,MC6]

| Wrapper / selector | Runtime flag zero: PC / bytes / u32 | Runtime flag nonzero: PC / bytes / u32 |
| --- | --- | --- |
| 0xfffffe000c6211d0 /0x13 | 0xfffffe000c6211f0 /20142000 /0x00201420 | 0xfffffe000c6211f8 /0000e0d4 /0xd4e00000 |
| 0xfffffe000c62120c /0x32 | 0xfffffe000c62122c /20142000 /0x00201420 | 0xfffffe000c621234 /0000e0d4 /0xd4e00000 |

The flag is the earlier transport-selection byte0xfffffe0007f8c7c8. Both wrappers call the captured original pre/post helpers; local source proofs cover X16 selector assignment and flag-dependent word location. In the new CPU chains, each wrapper has an explicit return model at entry: selector0x13 supplies the declared identifier and selector0x32 supplies a guarded private result-record address. No opaque word executes. Instruction names, receiver implementation, native return validation, allocation and record writes remain unknown. The source store now explains how CPU block[0] receives a pointer, while the pointer value and two record words still depend on explicit opaque-return/backing fixtures. [MC4,MC5]

Exact predecessor RAM and all tracked globals transfer into each succeeding call, with fresh declared registers/stack. The admission cut uses the source-initialized context and original descriptor helper; its two address-validation calls remain no-RAM models. A separately declared backend call takes that exact descriptor. Source-initialized context byte+0x76=1 keeps the earlier type3 bitmap branch inactive. File-zero CPU epoch0 becomes1; the backend publishes active=epoch=1 and nesting5 before its selector2 model, then clears active and restores nesting4. Status0/1 copies descriptor/auxiliary record words to the original output locations; raw statuses2/6 preserve output guards. Full gateway-to-backend execution and a continuous native startup/mapping epoch remain open. [MC5]

## Verification and limits

Twenty-three new nonvacuous source queries are UNSAT over102 distinct PCs/instruction instances with79 linked-edge obligations. They cover ARM root/call ABI, context scalar/vector stores, bitmap arithmetic, queue/count/policy stores, CPU addressing, identifier widths, result-pointer publication, selected-record conversion arithmetic, both wrapper dispatches and zero-count underflow. Two prior request/result ABI queries are re-solved. [MC6]

Ten configurations produce42 components and32 exact state joins: seven complete root/context/CPU/admission/backend chains, two root/context diagnostic chains and one root/context/CPU conversion-failure chain. They pass216 independent semantic checks, including all recorded global bytes and entire nonstack private RAM. Fresh replay checks19585 source visits over715 captured PCs,1849 reads/12560 B,1572 writes/11546 B,42 final boundaries,44040192 whole-private-RAM bytes and2078623 recorded-global bytes. It reconstructs73 original conversion entries,10 original bzero entries and21 transport-model entries, and independently checks95 leaf contracts,172 logical PAC steps and2540 logical64 B DC ZVA effects. [MC6]

Three source-NOP controls are rejected at root physical-word store0xfffffe000be74114, context geometry store0xfffffe000be60944 and CPU result-pointer store0xfffffe000be73634. Each fails the independent whole-region oracle. Positive counts exclude these rejection controls. Unexecuted captured PCs remain explicit in the receipt. Native PAC, cache effects, translation changes, SPTM receiver behavior and cross-CPU exclusion are not replay results. [MC6]

Extraction is O(K+I+W+F) time/space in collection bytes K, captured source I, scanned words W and fixups F. Local formula construction is O(I+Q) in source/formula DAG Q; SMT search is separately limited to30 s/query and has no asserted polynomial bound. Private execution/oracles/replay cost O(V+J+R) time/space in visits V, journal bytes J and checked RAM R. Each component uses1048576 B private RAM and a30000-instruction limit. All arithmetic is exact little-endian bit-vector arithmetic; empirical error bars do not apply. General native fallback/boot/transport cost remains unknown. JSON is archived with `zstd --ultra -22 -q -T1` and decoded roundtrip verification. Delivery rebuilds source/proofs/components/replay, verifies exact logical hashes/preserved originals, and scrubs decoded/nested content for analyst-local paths. [MC6]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| MC-A1: Pinned collection/compiler boundaries, literals/fixups and symbols identify this build | MC1-MC7 | Rehash inputs, reconstruct15 complete captures, match9 prior functions, retain4 unknown words, both fixups and all4 rows; reject cross-build inference |
| MC-A2: ARM source cuts begin with declared mid-frame inputs | MC2,MC5-MC7 | Original root and32 MiB call instructions execute; fresh state transfers and root-store control; full ARM initialization and native boot-root writer remain open |
| MC-A3: Lock/init/parser/capability/validation leaves follow their explicit no-RAM private contracts | MC2-MC7 |95 independently checked leaf contracts, guarded storage and exact model order/arguments; replacing a return model requires original effects and a new receipt |
| MC-A4: Declared table, topology, thread word and nonwrapping bounded allocations select the stated paths | MC3-MC7 | Three CPU blocks, unaligned/near-page bump inputs, N64/128/256/257/513/1024, original converters, disabled-conversion diagnostic; native range ownership/table producers remain open |
| MC-A5: Opaque identifier/result-pointer/status returns and result-record words are declared inputs | MC4-MC7 | Full/low16/low32 identifier control, statuses0/1/2/6, exact record/output guards, original pointer-store rejection; native wrapper receiver/record production remains unknown |
| MC-A6: Exact predecessor state may transfer across declared new-call epochs | MC5-MC7 |32 byte-exact RAM/global joins, fresh replay, source-produced descriptor and first epoch0->1; fresh registers/stack and one documented failure-feature change remain explicit |
| MC-A7: Local proofs/finite private executions establish this bounded increment | MC6,MC7 | Nonvacuous premises, unexecuted-PC list, three source controls, complete boundaries and all false native/full-goal flags; no native transaction claim |

## Architectural boundary and continuation

This advances the deeper pmap/SPTM prerequisite behind the previously recovered refill path. The new selectors0x13/0x32, raw pointer slots and conversion-table addresses are internal ABIs. They establish no additional incoming/outgoing Mach right, endpoint, right transfer or Mach message-emission site. Native daemon/user-client/provider transaction correlation remains unknown; the [Mach-port inventory](mach_ports_report.md) retains the existing endpoint evidence. The original boot-root, topology, shared-region and table producers still delimit external/environmental control; no direct daemon control of those globals is established. [MC7]

| Impact | Next discriminating work | Result it could establish |
| --- | --- | --- |
| High | Recover receiver-side selector0x13/0x32 and selector2 semantics and native record writer | Actual identifier domains, pointer lifetime, result layout/status and translation effects |
| High | Recover writers of boot root0xfffffe0007e6d838, converter globals and shared physical base0xfffffe0007e6d0b8 | Native root/range/CPU backing provenance replacing environmental fixtures |
| High | Execute complete gateway/category/expansion path with original validation and transport effects | Continuous request flow beyond the current admission-to-backend call boundary |
| Medium | Recover original CPU caller0xfffffe000be780f8 and full topology enumeration | CPU initialization order, index admission and native block/descriptor lifetime |
| Medium | Establish count admission and nonwrapping allocation/conversion prerequisites upstream | Whether N=0, small counts or wrapping byte budgets are excluded before this initializer |
| Medium | Recover original parser/capability/init/lock leaves and read-side epoch/ready protocol | Boot overrides, initialization visibility, progress and exclusion |
| High | Pair the daemon/provider boundary with kernel mapping effects in one observed transaction | Actual fairplayd/FairPlayIOKit payload, status, ownership and epoch correlation |

**QG1** Pass: factual technical analysis. **QG2** Pass: MC-A1-MC-A7 identify assumptions/dependencies and falsification probes. **QG3** Pass for this increment: routine roles, producer/consumer ABI, data/control/environment flow, lower emission locations and Mach inventory impact covered; full investigation remains active. **QG4** Pass: widths, byte extents, signed shifts, modular/carry behavior, units and complexity explicit. **QG5** Pass: prior fixture/new geometry difference, three identifier widths, N=0 versus small-count diagnostics, partial/native epochs and opaque pointer origin separated. **QG6** Pass: pinned original bytes/fixups/literals/symbols/diagnostics, reconstructed source queries and fresh independent replay; unknown receiver/native behavior explicit. **QG7** Pass: bounded impact-ranked continuation recorded. `full_goal_complete=false`. [MC1-MC7]


## SPTM boot record and nested initialization follow-up

The [SPTM boot-input report](kernel_sptm_boot_inputs_report.md) replaces this report's modeled0xfffffe000be71258 leaf with original pool/shared allocation, original device-tree helper execution and a restored-frame CPU tail call. CPU initialization returns to0xfffffe000be609bc inside the context initializer before its bitmap allocation. The new versioned publisher supplies converter globals and transport byte; the topology pointer is an original chained fixup. This report's separate CPU component remains a conditional earlier model; the follow-up establishes actual nested source order and shared-base production. Native boot inputs/backing and opaque return semantics remain unknown.


## Collection entry and copied-header follow-up

The [boot-header handoff](kernel_boot_header_handoff_report.md) replaces the separately seeded root/device structure in its new chains with two original memcpy calls and source pointer publication. Header+0x1d8 copies to0xfffffe0007e6d838; the same copied header at0xfffffe0007e6d660 supplies the original context/pool count and raw device fields. Native root ownership and opaque return effects remain unknown.
