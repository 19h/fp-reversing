# pmap admission, descriptor construction and SPTM transport

The refill adapter's lower routine0xfffffe000be5b2e8 is identified by its original diagnostics as `pmap_enter_options()`. Its selected backend reaches a three-wrapper SPTM interface: the first wrapper has the exact nlist name `_sptm_retype`; the mapping-request wrapper sets X16=2. Original source establishes admission gates, descriptor arithmetic, a per-CPU request/result protocol and the two transport-word locations. Native translation changes and the opaque transport's return ABI remain unknown. [MT1-MT7]

```text
prior original refill -> per-page adapter -> pmap_enter_options-style gateway
  alignment mask; context bounds; CPUWINDOWS exclusion; protection gates
    original descriptor helper -> raw descriptor + u16 attributes
      [remaining full-gateway paths are outside the executed cuts]
        selected implementation, declared call epoch
          classify mapping categories
          nesting += 1; epoch += 1; active = epoch; DMB ISH
          wrapper(X0=context[+8], X1=VA, X2=descriptor, W3=0)
            original prehelper: nullable thread; nesting += 1
            X16=2; runtime byte selects one of two opaque words
              STOP before either word; native effects unknown
            original posthelper [separate component]
          [explicit no-RAM wrapper-result model in implementation cases]
          unsigned W0 < 2 -> copy two words from declared CPU result record
          release-store active=0; nesting -= 1; return raw status
```

Primary provenance is the pinned original kernel collection, SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, compiler function starts, nlist records, original diagnostics and original instruction bytes. Preserved normalized kext SHA-256 is `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. This increment does not derive new facts from another build. An attempted IDA MCP availability check returned an unavailable authenticated bridge; no successful new IDB read or mutation is claimed. Unknown instruction words remain unknown. [MT1,MT7]

| Complete interval, end exclusive | Words | Bytes | Established role |
| --- | ---: | ---: | --- |
| 0xfffffe000be5b2e8..0xfffffe000be5c0bc | 885 | 3540 | Gateway identified by pmap_enter_options diagnostics |
| 0xfffffe000be5ca04..0xfffffe000be5cc60 | 151 | 604 | Descriptor and u16 attribute construction |
| 0xfffffe000be5ce90..0xfffffe000be5d234 | 233 | 932 | Selected mapping backend and CPU result handling |
| 0xfffffe000be5de8c..0xfffffe000be5e028 | 103 | 412 | Current/desired mapping category bytes |
| 0xfffffe000be5c0bc..0xfffffe000be5ca04 | 594 | 2376 | Alternate expansion/table-walk path; captured, not executed |
| 0xfffffe000bc9c090..0xfffffe000bc9c0fc | 27 | 108 | Transport prehelper |
| 0xfffffe000bc9c0fc..0xfffffe000bc9c184 | 34 | 136 | Transport posthelper |
| 0xfffffe000c620b7c..0xfffffe000c620bb8 | 15 | 60 | Exact symbol _sptm_retype; selector1 |
| 0xfffffe000c620bb8..0xfffffe000c620bf4 | 15 | 60 | Mapping-request transport; selector2 |
| 0xfffffe000c620bf4..0xfffffe000c620c30 | 15 | 60 | Adjacent transport; selector3 |
| 0xfffffe000c6456f8..0xfffffe000c6457b8 | 48 | 192 | Address-validation-like helper; explicit return model in admission cases |
| Total | 2120 | 8480 | Six opaque words retained individually |

Only `_sptm_retype` has an exact nlist name among these eleven starts. Direct callees include the exact `_panic`, `___stack_chk_fail` and `_assert_wait` symbols. The extractor retains116 direct call sites and eight original diagnostic strings, including `pmap.c`, `invalid mapping type: %d`, and the `sptm_get_paddr_type` failure diagnostic. Descriptive names for other routines do not assert exact exported symbol identity. [MT1]

| Claim | Established result | Dependencies |
| --- | --- | --- |
| MT1 | Original function/word/diagnostic custody and bounded role identification | MT-A1 |
| MT2 | Gateway admission and descriptor argument/bit contracts | MT-A1-MT-A3 |
| MT3 | Selected mapping-category fallback and per-CPU request/result protocol | MT-A1-MT-A4 |
| MT4 | Exact wrapper selectors, branch byte and opaque emission PCs | MT-A1,MT-A4,MT-A5 |
| MT5 | Descriptor same-value joins and the remaining native/epoch limits | MT-A1-MT-A6 |
| MT6 | Symbolic checks, private oracles, independent replay and controls | MT-A1-MT-A7 |
| MT7 | Mach inventory, external-control boundaries and bounded continuation | MT-A1-MT-A7 |

Artifacts: [extractor](triage_evidence/recover_kernel_mapping_transport.py), [private executor and oracles](triage_evidence/probe_kernel_mapping_transport.py), [independent replay](triage_evidence/replay_kernel_mapping_transport.py), [source audit](triage_evidence/audit_kernel_mapping_transport.py), [delivery verifier](triage_evidence/verify_kernel_mapping_transport_delivery.py), [source capture](triage_evidence/kernel_mapping_transport_checks.json.zst), [audit receipt](triage_evidence/kernel_mapping_transport_audit.json.zst). Decoded capture SHA-256: `7e06d78a53ee5254a411b7cf20e9286add73c8a08ba0e152f2d9f13cb0f15840` (311698 B). Decoded audit SHA-256: `f0485639b36f9c23510855c8525b87bfb75034bb98767dda38871760993608aa` (2371735 B). [MT6]

## Admission and descriptor contract

The [refill publication report](kernel_refill_publication_report.md) established the incoming nine-argument request. Gateway entry preserves X0=context, X1=VA, X2=physical byte address, W3=protection/mode, X4=options, X5=another option field, X6=descriptor flag, X7=request flags, and the low byte of the ninth stack argument. The two calls to0xfffffe000c6456f8 receive u64[context+8] and PA respectively. That helper is captured but remains a no-RAM return model in these admission components; its complete native effects are unknown. [MT2,MT5]

Geometry is u64[context+0x20]. With rows=u64[geometry], selector=u32[geometry+0x48], the alignment-mask address uses offset `56*zero_extend(selector)+8`. If this u64 offset differs from sign-extended low32(offset), source poisons the candidate address's upper16 bits with0x2bad. Otherwise it uses rows+offset. Both VA and PA are tested against the loaded mask. The main declared geometry mask is0x3fff, requiring16384 B alignment. This is a fixture-derived alignment value; the source proof covers arbitrary masks. [MT2]

| Check | Original control site | Outcome established here |
| --- | --- | --- |
| VA & mask !=0 | 0xfffffe000be5b390 /0xfffffe000be5b394 | Exact original VA diagnostic before _panic |
| Kernel context and VA in [0xfffffecfffd00000,0xfffffecfffe00000) | 0xfffffe000be5b3a8..0xfffffe000be5b3cc | CPUWINDOWS diagnostic; half-open extent1048576 B |
| PA & mask !=0 | 0xfffffe000be5b3d0 /0xfffffe000be5b3d4 | Exact original PA diagnostic before _panic |
| VA below u64[context+0x10] or at/above u64[context+0x18] | 0xfffffe000be5b3d8..0xfffffe000be5b3ec | Original raw W0=1 return at0xfffffe000be5bf4c |
| Kernel context and W3 bit2 set | 0xfffffe000be5b400 /0xfffffe000be5b404 | Original diagnostic names an executable kernel mapping |
| W3=4 and geometry byte+0x4c bit0 clear | 0xfffffe000be5b408..0xfffffe000be5b41c | Original raw W0=2 return at0xfffffe000be5bfc8 |
| Request X7 bit1 set | 0xfffffe000be5b420 | Restored-frame tail call to0xfffffe000be5c0bc(context,VA,flags,geometry selector) |

The CPUWINDOWS diagnostic explicitly identifies kernel_pmap and both range constants. This supports the context's role and relates the gateway exclusion to the per-CPU temporary windows in the [physical-zero report](kernel_physical_zero_report.md). The on-disk128 B at context0xfffffe000cb0bf18 are all zero. Runtime bounds, geometry and root values in this report's original executions are declared fixtures; the follow-up below recovers their source initializer. No claim that daemon input can directly supply those fields follows. [MT2,MT7]

For admitted ordinary requests, the gateway calls descriptor helper0xfffffe000be5ca04 with X0=context, X1=PA&0xfffffffff000, W2=protection, X3=original X4, X4=original X6, X5=original X7 and X6=&u16[FP-0xa2]. The helper first clears that u16, constructs raw descriptor bits, and sets bit10 on every normal return. Its initial value is3 if W4=0, otherwise0x0400000000000003 (bit58 plus3). PA contributes only mask0xfffffffff000 at that stage. Geometry fields, protection, context kind, option bits and physical-page metadata select later bits; their architectural permission/cache names remain unknown except where an original diagnostic supplies a name. [MT2]

The selected kernel-context protection3 path ORs u64[geometry+0x30], preserves bit58 when W4!=0, emits u16 attributes0xc0, and sets bit10. For the explicit PA0x400000 and geometry field0x0020000000000000, the result is0x0420000000400403. Kernel protections0/1 instead add0x80 and emit0x40 in the checked family. The nonkernel fixtures keep context bytes+0x75/+0x76 zero, request option bit22 clear and PA outside the declared direct interval; their checks cover modes0/1/2/3/4/7, geometry-feature states, mode4 rejection and W4 zero/nonzero. This is not a universal interpretation of every descriptor-helper branch. [MT2,MT5]

## Selected backend and CPU state

Backend0xfffffe000be5ce90 receives context in X0, output2 pointer in X1, descriptor in X2, auxiliary X3, output5 pointer in X4, VA in X5, options in X6, mapping tag in X7 and a ninth pointer on the stack. The category helper initializes two output bytes to0x0b. Explicit tag0x23 with global byte0xfffffe0007e6dc18 bit0 clear retains desired0x0b and returns without querying the current PA type. With the feature set, another desired-category path is selected. Category mismatch and retyping paths are captured; they are outside this increment's executed backend cases. [MT3]

For equal categories, source increments u32[TPIDR_EL1+0x1c8], reads signed64[thread+0x1b8] and computes CPU block `0xfffffe000cac8000 + (value ASR16)`. It increments u64[block+0x1278], writes the same value to u64[block+0x1270], then executes DMB ISH. The source formulas permit u32/u64 wrap; the finite fixtures use nesting4 and epoch7. The encoded thread word selecting CPU0/1/2 and a16384 B stride is declared, not an inferred general native thread-field layout. [MT3]

For context byte+0x76=3 and VA inside the optional context+0x40/+0x48 interval, the source indexes a two-bit bitmap using geometry and context+0x60. Its selected field's high bit conditionally ORs descriptor0x800. Both field0 and field2 execute: field0 leaves the descriptor unchanged; field2 adds0x800. A local arbitrary-word proof checks that polarity and the two-bit shift. [MT3]

| Transfer | Exact original source contract |
| --- | --- |
| Call at0xfffffe000be5d03c | X0=u64[context+8], X1=VA, X2=possibly bitmap-adjusted descriptor, W3=0; target0xfffffe000c620bb8 |
| Raw result gate at0xfffffe000be5d040 /0xfffffe000be5d044 | Unsigned W0>=2 bypasses both result copies |
| CPU result record | R=u64[CPU block]; source reads u64[R] and u64[R+8] |
| Copy at0xfffffe000be5d058 | u64[original argument5]=u64[R] |
| Copy at0xfffffe000be5d060 | u64[original argument2]=u64[R+8] |
| Completion | Release store of zero to CPU block+0x1270; nesting decrement; raw status preserved on checked paths |

The CPU result pointer/words in these original components are seeded fixtures; the follow-up recovers the slot writer while retaining explicit opaque-return/record fixtures. The explicit wrapper-result model modifies caller-clobbered registers and NZCV, returns one of0/1/2/6/7/0xffffffff, and has no RAM effects. Consequently the tests establish how source consumes a declared result record, not that transport produces that record. The first result word equals the requested descriptor in these cases, selecting the direct consistency path. Compressed-PTE diagnostics, alternate old-PTE cases, result-dependent accounting, category mismatch and deferred scheduler paths need separate work. Status values are raw; no new native error-name or mapping-success classification is asserted. [MT3,MT5]

## Transport words and environmental boundary

Each wrapper calls the original prehelper, sets X16 to its selector, reads byte0xfffffe0007f8c7c8, and chooses its transport word. It then calls the original posthelper and restores its frame. The prehelper preserves X0-X7 and incoming X16, increments nesting when TPIDR_EL1!=0, reads system register s3_6_c15_c8_0, and spins at0xfffffe000bc9c0d0 if that read is nonzero. The private model supplies zero for that read. The posthelper preserves X0-X7, decrements nonnull-thread nesting and has a DAIF/deferred-work branch. The depth1 component supplies DAIF0x80 to take its masked branch; depth4/6 and null-thread components cover other direct returns. These logical system reads do not recover live hardware values. [MT4]

| Selector / exact name | Flag zero: PC / little-endian bytes / u32 | Flag nonzero: PC / little-endian bytes / u32 |
| --- | --- | --- |
| 1 / _sptm_retype | 0xfffffe000c620b9c /20142000 /0x00201420 | 0xfffffe000c620ba4 /0000e0d4 /0xd4e00000 |
| 2 / unknown exact name | 0xfffffe000c620bd8 /20142000 /0x00201420 | 0xfffffe000c620be0 /0000e0d4 /0xd4e00000 |
| 3 / unknown exact name | 0xfffffe000c620c14 /20142000 /0x00201420 | 0xfffffe000c620c1c /0000e0d4 /0xd4e00000 |

The reference decoder does not decode these six words. Extraction walks every4 B word independently, retaining `.word` entries and exact byte hashes; it never truncates a function at an undecoded word. Private wrapper components stop before the selected word. Neither word's instruction name, exception level, receiver implementation, native register clobbers nor translation effects is established here. X16 selectors are not Mach message IDs or port names. No new receive/send right, right transfer, Mach endpoint or Mach message-emission location is established. [MT1,MT4,MT7]

## Verification, assumptions and continuation

Twenty-two nonvacuous source queries are UNSAT over97 distinct PCs/instruction instances and75 linked-edge obligations. They cover row addressing/poisoning, arbitrary-mask alignment, bounds and CPUWINDOWS edges, descriptor ABI/bit construction, epoch publication, request/result ABI, bitmap polarity, category fallback and three wrapper dispatches. Two retained source queries for the earlier PFN/request adapter are re-solved. Local memory proofs establish sequential byte effects; DMB/release opcodes do not prove native exclusion or cross-CPU ordering in this model. [MT6]

Seventy components pass338 independent semantic checks:12 gateway cuts,22 descriptor calls,20 backend calls,12 wrapper-entry cuts and4 posthelper calls. Eighteen exact descriptor-value links connect source-produced kernel/protection3 results to backend entry values in separately declared epochs. This proves same-value compatibility, not complete gateway-to-transport or native execution. Fresh replay checks4422 source visits/467 captured PCs,1116 writes/7901 B,1145 reads/7803 B,70 final boundaries,73400320 whole-private-RAM bytes and105186 recorded-region bytes. It also reconstructs20 transport entries and checks44 leaf models,13 logical system reads and189 logical PAC steps. All nonstack private RAM and every recorded image-region guard are checked. [MT5,MT6]

Three source-NOP controls are rejected: epoch store0xfffffe000be5cf9c, result copy0xfffffe000be5d058 and selector2 assignment0xfffffe000c620bc8. They fail the independent epoch, result-copy and selector oracles respectively. Unexecuted captured PCs are retained explicitly. JSON archives use `zstd --ultra -22 -q -T1`, with decoded roundtrip verification. Delivery reconstructs extraction, proofs, components and independent replay; checks decoded/nested content for analyst-local paths; and verifies exact owned files, logical hashes, preserved original inputs and publication state. [MT6]

Extraction is O(K+I+S) time/space in pinned collection bytes K, captured words/bytes I and scanned symbols S. Formula construction is O(I+Q) in source and query DAG Q; SMT search has no asserted polynomial bound and is limited to30 s/query. Private execution, oracle construction and replay are O(V+J+R) time/space in source visits V, journal bytes J and checked RAM R. Full-gateway/native transport progress and complexity remain unknown. [MT6,MT7]

| Assumption | Used by | Stress test / falsification probe |
| --- | --- | --- |
| MT-A1: Pinned collection, compiler starts and original symbols/strings identify this build | MT1-MT7 | Rehash originals, reconstruct eleven complete captures, retain all six undecoded words and exact nlist results; no cross-build equivalence |
| MT-A2: Gateway context, geometry, bounds, root and helper return contracts are declared | MT2,MT5-MT7 | Zero-filled on-disk context retained;12 admission cuts include alignment, both bounds, reserved endpoints, executable rejection, feature and tail-call controls; recover actual boot writer separately |
| MT-A3: Descriptor fixtures select the stated mode/option/context/physical-interval family | MT2,MT5,MT6 |22 calls vary kernel/user, modes, geometry feature and W4; source-local arbitrary-value bit contracts; unexecuted branches remain listed |
| MT-A4: Thread/CPU fields, result record, category feature and raw transport returns obey explicit private contracts | MT3-MT7 | Three declared CPU blocks, six statuses, both bitmap polarities, guarded RAM, argument/result oracles and source-store controls; native result production remains unknown |
| MT-A5: Logical PAC and supplied system reads qualify private source replay only | MT4,MT6,MT7 | Fresh CPU checks all visits/effects and13 logical reads; wrapper cases stop before transport; actual special-register, DAIF, authentication and scheduler behavior remain unknown |
| MT-A6: Equal values may compose across separately declared component calls | MT5-MT7 |18 source descriptor/backend value links; prehelper nesting5->6 and separate posthelper6->5 checked; no claim of full native call/ownership epoch |
| MT-A7: Finite components and local UNSAT contracts support only this increment's scope | MT6,MT7 | Record unexecuted PCs, three rejected source controls, complete boundaries/guards and explicit false native/full-goal flags |

| Impact | Next discriminating work | Result it could establish |
| --- | --- | --- |
| High | Recover receiver-side semantics for the two original transport words and selector2 | Actual translation operation, result-record producer, native status and register effects |
| High | Recover initialization/writers of context0xfffffe000cb0bf18 and the CPU result-pointer slots | Source-produced bounds/root/geometry and storage ownership, replacing declared state |
| High | Join complete gateway, category/expansion paths and backend without no-RAM leaves | Continuous selected refill-to-translation request and exact retry/error origins |
| Medium | Recover tag0x23 feature producer, current-type lookup and _sptm_retype transitions | Category policy, feature-dependent behavior and page lifetime constraints |
| Medium | Resolve nesting/deferred-work and epoch reader counterparts | Progress, synchronization and cross-CPU protocol beyond sequential private effects |
| Low | Decode geometry selectors and architectural names of remaining descriptor bits | Portable layout/permission vocabulary while preserving build-specific raw contracts |

**QG1** Pass: factual technical analysis. **QG2** Pass: MT-A1-MT-A7 identify dependencies and falsification probes. **QG3** Pass for this increment: roles, lower ABI/emission sites, data/control/environment context and Mach-inventory impact covered; full goal remains active. **QG4** Pass: byte extents, u16/u32/u64 widths, signed ASR, modular arithmetic, bounds and algorithmic costs explicit. **QG5** Pass: opaque transport, source components, declared results and native gaps remain distinct; no unresolved result contradiction. **QG6** Pass: claims pinned to original bytes/strings/symbols and reproduced receipts; unavailable IDA and unknown words explicit. **QG7** Pass: impact-ranked bounded continuation above. [MT1-MT7]


## Context and CPU initialization follow-up

The [mapping context report](kernel_mapping_context_report.md) recovers the original context initializer and CPU result-pointer store. The actual geometry field+0x30 is0x0060000000000000, producing descriptor0x0460000000400403 in the selected protection3 path; this report's0x0420000000400403 remains valid for its original declared geometry. Source-initialized context byte+0x76=1 bypasses the optional type3 bitmap branch, and file-zero CPU epoch0 advances to1 in the follow-up chains. The CPU result-pointer slot is written from selector0x32's raw return after selector0x13 provides an identifier; native receiver-side pointer/record production remains unknown. Seven private producer-to-consumer chains transfer exact state, while fresh call registers/stack, validation and opaque-return models remain explicit.


## SPTM boot record and nested initialization follow-up

The [SPTM boot-input report](kernel_sptm_boot_inputs_report.md) recovers the publisher of transport-selection byte0xfffffe0007f8c7c8: for version>=7 it is bit6 of embedded record+0xa8. Earlier versions preserve that byte, including a declared downgrade case. The header caller checks magic0xd00f000000000000 and passes header+0x1a0. Original converter and nested pool/CPU initialization now consume the source-published state. Receiver-side transport semantics, translation and native ownership remain unknown.


## Collection entry and copied-header follow-up

The [boot-header handoff](kernel_boot_header_handoff_report.md) identifies the original cold-entry selector15 boundary and copies entry X2 into the kernel header whose+0x1d8 supplies the physical root used by later mapping requests. This establishes source origin and private composition, while native lower-transport receiver/return effects and matched daemon transactions remain open.
