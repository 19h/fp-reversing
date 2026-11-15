# User-client caller cleanup, copy-back and return

The selected caller cleanup destroys its parsed container using callback0x1a, optionally requests retirement of an auxiliary buffer, decodes the original protected staging buffer back into the saved caller buffer, and requests retirement of the staged allocation, outer typed context and aligned workspace. On ordinary callee returns and equal saved/current canaries, W0 is the retained raw status XOR `0x31ae0066`. The original staging-allocation null-result seam bypasses copy-back and staged retirement and joins outer cleanup. These are conditional source contracts; native allocator effects, complete incoming-state identity and successful daemon/provider delivery remain unknown.

## Evidence and claim register

Primary evidence is the original kernel collection and normalized FairPlayIOKit image. The [extractor](triage_evidence/recover_userclient_caller_return.py), [source audit](triage_evidence/audit_userclient_caller_return.py) and [delivery verifier](triage_evidence/verify_userclient_caller_return_delivery.py) preserve source words, original fixups, symbols, descriptors, bank identities and reproducible queries in [checks](triage_evidence/userclient_caller_return_checks.json.zst) and [audit](triage_evidence/userclient_caller_return_audit.json.zst).

| Claim | Established result | Dependencies |
| --- | --- | --- |
| CR1 | Outer requests are `_IOMallocAligned(16384,64)` and `_IOMallocTypeImpl` with a declared4,096 B descriptor; returned workspace/context roots are distinct | CR-A1-CR-A4 |
| CR2 | Original aliases distinguish C+0x90 staged pointer, C+0x3c0 auxiliary pointer and S+0xbe4 encoded auxiliary extent; final staged extent comes from the original argument's low32 bits | CR-A1-CR-A4 |
| CR3 | Caller cleanup saves arbitrary raw status at S+0xde4 and installs callback0x1a while destroying the container/list and clearing C+0x600 | CR-A1-CR-A5 |
| CR4 | Null auxiliary pointer skips data retirement; nonnull pointer requests `_IOFreeData` using its own decoded u32 extent | CR-A1-CR-A6 |
| CR5 | Nonzero staged count selects a finite reverse copy-back; each protected byte decodes into the saved caller buffer, while zero count skips the loop | CR-A1-CR-A6 |
| CR6 | Staged retirement uses the original low32 extent; context and aligned-workspace retirement requests use their distinct pointer/descriptor/size channels | CR-A1-CR-A7 |
| CR7 | Equal-canary ordinary cleanup returns raw_status XOR SUCCESS; unequal canary selects the original `___stack_chk_fail` veneer | CR-A1-CR-A7 |
| CR8 | A null staging-allocation result retains the saved status and joins outer cleanup without copy-back or staged retirement | CR-A1-CR-A7 |
| CR9 | 690 selected instruction locations, 44 nonvacuous new UNSAT queries, six predecessor rechecks, 3,584 bank cases and four altered-evidence equality controls support these bounded results | CR-A1-CR-A8 |

Pinned normalized source SHA-256: `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Original kernel collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Every selected instruction word agrees across both images. The controller `0xfffffe000a635208`..`0xfffffe000a666930` exclusive has50,634 words and byte SHA-256 `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297`; the separately captured guard-failure veneer lies outside it.

Decoded checks SHA-256: `802b374a4e8976848a3b3613118df5c0ad61a64a485ec38c9615bed8240195be`. Decoded audit SHA-256: `811105978a9b041f767603d1fc548c2b2c4121826edebb6005e2dd8a5f1beca1`. There are43 selected spans,29 separately captured branch/call instructions,14 bank rules, four typed descriptor records and4,722 proof instruction instances. A further76 original instructions are checked structurally in the outer-allocation retention range and frame prologue/epilogue. The direct guard-failure BL is separately frozen. None of this establishes native pointer authentication.

## Allocation requests, retained roots and sizes

C denotes selected context X2, S selected workspace/state X4 and F selected SP. P is the saved original caller-buffer pointer, Z the staged protected buffer, H the parsed container, J a list node, A the optional auxiliary buffer and M its u32 extent. R is retained raw status. `SUCCESS=0x31ae0066`, `TOKEN=0x886a1ca3`, `PHASE=0x7795e642`. All sizes below are bytes.

| Resource / channel | Original request or producer | Retained identity / selected retirement |
| --- | --- | --- |
| Workspace S | `0xfffffe000a6353dc`: `_IOMallocAligned`, X0=16,384, X1=64 alignment | Result to X24 at `0xfffffe000a6353e0`; final `_IOFreeAligned(S,16384)` at `0xfffffe000a6662b0` |
| Outer context C | `0xfffffe000a635470`: `_IOMallocTypeImpl`, X0=`0xfffffe000847bea0` | Result to X23 at `0xfffffe000a635474`; final `_IOFreeTypeImpl(0xfffffe000847ba60,C)` at `0xfffffe000a666260` |
| Staged buffer Z | Existing input staging requests `_IOMallocData` for N=low32(saved X1) | C+0x90, addressed by F+0x670; `_IOFreeData(Z,ZE64(N))` at `0xfffffe000a666188` |
| Original caller buffer P | Original entry X0 saved at F+0x8f8 | Copy-back destination at `0xfffffe000a6660f4`; this path does not request its retirement |
| Auxiliary A / M | C+0x3c0 / S+0xbe4 encoded as M XOR SUCCESS | F+0x728 / F+0x888; optional `_IOFreeData(A,ZE64(M))` at `0xfffffe000a665f58` |
| Parsed H | C+0x600, addressed by F+0x988 | Selected shared container destructor; clears that output cell before caller callback |

The allocation-phase source requests both outer allocations and retains their returned roots. The48-instruction range `0xfffffe000a635478`..`0xfffffe000a635538` exclusive contains two ordinary calls and no instruction writing X23/X24. Under the ordinary callee-preservation premise, those values survive to the [staging report's](userclient_container_staging_report.md) original C/S alias stores. Allocation success, native allocation identity and the full intervening initialization effects remain separate premises. Earlier C/S symbolic subranges describe accessible proof storage, not these newly recovered outer allocation-request extents.

| Outer typed site | Address | Name / flags / declared size / signature |
| --- | --- | --- |
| Allocation | `0xfffffe000847bea0` | site.AllocType /0xe4 /4,096 B /512 ASCII `1` bytes |
| Retirement | `0xfffffe000847ba60` | site.AllocType /0xe4 /4,096 B /512 ASCII `1` bytes |

The two normalized64-byte records match. Original chained pointer fields, full name/signature strings and scalar metadata are checked independently. Distinct site addresses remain distinct; matching metadata does not establish native type-site bookkeeping or interchangeability.

## Caller-specific container cleanup and auxiliary buffer

The [command-dispatch report](userclient_command_dispatch_report.md) reaches common cleanup `0xfffffe000a656f00` with W3/W10=TOKEN. The store at `0xfffffe000a656f24` saves R at S+0xde4. W24 becomes0x1a. Null H selects `0xfffffe000a665e90`; nonnull H selects `0xfffffe000a656f4c`, which loads &C+0x600 into X19 and joins the shared destructor through `0xfffffe000a66229c`.

Unlike the parser-failure caller's callback0x50, this caller stores table[0x1a]=`0xfffffe000a665e90` at C+0x368. The original [destructor source](userclient_parser_cleanup_report.md) is composed again with this callback and output cell. Empty H requests container typed retirement. For each valid list node, it saves next before optionally requesting buffer data retirement, clears a nonnull retired-buffer cell after ordinary return, requests node typed retirement and selects next or final container retirement. The final container return clears C+0x600, restores the selected phase tokens and selects callback0x1a. R survives in S+0xde4 while X23 is reused as the current node.

| Retirement request | Original call PC | Arguments |
| --- | --- | --- |
| Node buffer | `0xfffffe000a6607e8` | `_IOFreeData(J.buffer,ZE64(J.extent32))` |
| List node | `0xfffffe000a660708` | `_IOFreeTypeImpl(0xfffffe000847be20,J)`; declared32 B site.FPTTLVNode |
| Container | `0xfffffe000a6605c4` | `_IOFreeTypeImpl(0xfffffe000847bde0,H)`; declared16 B site.FPTTLV |

At callback entry, `0xfffffe000a665eb0` loads A through F+0x728. A=0 skips data retirement; A!=0 requests `_IOFreeData` at `0xfffffe000a665f58`. X1 is the zero-extended value of `[S+0xbe4] XOR SUCCESS`, not the staged count N. After ordinary return, C+0x3c0 still contains A in the selected source. No alias-complete pointer clearing is established.

The original staging completion explicitly initializes C+0x3c0=0 and S+0xbe4=SUCCESS, hence decoded M=0. The producer of a later nonzero auxiliary result is not recovered here. A is not identified as Z: Z is independently retained at C+0x90. Both null and nonnull auxiliary routes reach the same count-controlled staged copy-back contract after reloading R from S+0xde4.

## Original size custody and finite protected copy-back

The selected original argument channel is u64 at F+0x878, but the staging count is N=low32(argument). The original codec at `0xfffffe000a6356ac`..`0xfffffe000a6357b4` exclusive produces a u64 retained value; `0xfffffe000a641c84` saves it at S+0xe10:

```text
E64 = ZE64(N) + 0x621745fcc03f95d4             (mod 2^64)
N64 = E64 + 0x9de8ba02b7564d89 + 0x886a1ca3  (mod 2^64)
    = ZE64(N)
```

The arbitrary-u64-argument proof establishes that the upper32 argument bits do not contribute to this count. This is a source width contract, not a claim about admissible native external lengths.

After auxiliary handling, `0xfffffe000a665f98` reloads R into W19, and `0xfffffe000a665fa0` loads Z through F+0x670. The source at `0xfffffe000a665fcc` recovers `ZE64(N XOR 0xc03f95d4)` and compares it with `0xc03f95d4`. N=0 selects staged retirement directly; N!=0 selects `0xfffffe000a66609c`. Copy preparation sets unsigned64 counter J=ZE64(N), source Z, destination P, K0=`0x02e859d27e491464` and K1=`0x4dae26df20976138`.

For each 1<=J<=ZE64(N), the nominal pointer path performs:

```text
j = J - 1
a = Z + j
mask8(a) = low8((((ROR64(a & ~7,8) + K0) XOR K1)
                >> ((a & 7) * 8)))
P[j] = stored[a] XOR mask8(a)
J = j
continue if J != 0
```

The byte load is at `0xfffffe000a6660d4`; the destination store is at `0xfffffe000a6660f4`. The audit proves the exact decoded byte and destination, both accesses inside their N-byte spans, preservation of all live loop/retirement inputs, and strict unsigned-rank decrease without wrapping. The initial N>0 gate and last-iteration J=1 case provide the finite induction certificate: exactly N reverse steps, then `0xfffffe000a666118`. All these claims require the explicit nominal pointer guards and stable, separate accessible source/destination storage. The alternate MOVK at `0xfffffe000a6660d0` is separately checked only as a bit transform.

The [staging report's](userclient_container_staging_report.md) initial protected copy uses the same mask/key pair and is independently rechecked. Unchanged protected bytes therefore decode back to their original values. The current staged-byte contents are otherwise arbitrary: this increment does not identify which command paths modify them or establish equality of the final caller buffer with initial input.

## Retirement order and guarded status result

At `0xfffffe000a666188`, `_IOFreeData` receives X0=Z and X1=ZE64(N), using the original E64 size channel rather than the auxiliary extent. This request is proved for zero N and after a final nonzero copy iteration. Its return moves R from W19 into callee-saved W26 and reloads C/S. The final context request sets W23=SUCCESS, requests the distinct outer retirement descriptor and preserves S for the next request. The next ordinary return requests `_IOFreeAligned(S,16384)`. No subsequent selected instruction reads C or S before the guard/result epilogue; native callee effects and surviving aliases remain unknown.

```text
common cleanup: save R -> S+de4
  -> H list/container retirement requests, if H!=0; clear C+600
  -> optional data retirement of A using M
  -> decode Z[N-1..0] back into caller P, if N>0
  -> data retirement request Z, N
  -> typed retirement request C, declared4096 B
  -> aligned retirement request S, 16384 B
  -> saved/current canary equal: W0 = R XOR 31ae0066
     unequal: call through original ___stack_chk_fail veneer

staging allocation result Z=0
  -> retain F+9ec raw status in W26
  -> join context/workspace retirement and guarded result
```

The ordinary frame relation is X29=F+0x10e0; the saved guard occupies F+0x1060. Original prologue instructions reserve0x80+0x1070=0x10f0 B and establish that relation, conditional on the stack-probe/ordinary frame premise. Original save `0xfffffe000a635264` and reload `0xfffffe000a6662b4` use the same FP-relative slot. Current guard is loaded through original slot `0xfffffe000847c5f8` to kernel symbol `___stack_chk_guard` at `0xfffffe000cacb000`.

The branch at `0xfffffe000a6662c8` selects `0xfffffe000a66692c` when the guard differs. That original BL reaches veneer `0xfffffe000a69f294`; slot `0xfffffe000847c478` resolves to kernel `___stack_chk_fail` at `0xfffffe000c629694`. This establishes the selected failure request, not native delivery or behavior of the callee.

On equal canaries, `0xfffffe000a6662cc` writes W0=W26 XOR W23=R XOR SUCCESS. The11-instruction epilogue restores a net0x10f0 B of SP and does not write W0/X0; its original terminal instruction is RETAB. Successful PAC authentication and a native return are not asserted. Raw SUCCESS consequently decodes to zero, but no external errno/IOReturn naming is assigned to other decoded values.

For the null staging-allocation source seam, the original result block at `0xfffffe000a641cfc`..`0xfffffe000a641d50` exclusive saves null at C+0x90, loads raw status from F+0x9ec into W26 and selects `0xfffffe000a6661bc`. It does not join the earlier container/auxiliary/copy-back path. The selected context/workspace requests and equal-canary result are composed from this incoming phase. The origin and native interpretation of every possible F+0x9ec value remain outside this increment.

## Original bank and private table custody

| Rule | Left / right | Key / constant / additive / bias | Slot / target |
| --- | --- | --- | --- |
| workspace_allocate | 0xfffffe0007949dd0 / 0xfffffe000792fbc0 | 0x5c / 0xd2 / 0xe69 / 0x0 | `0xfffffe000847a8f8` / `0xfffffe000c4b9a08` |
| allocation_table | 0xfffffe0007941f60 / 0xfffffe000794a0d0 | 0x6d / 0x13 / 0x20 / 0xfffffffffffffff4 | `0xfffffe0008472098` / `0xfffffe0008472f20` |
| context_allocate | 0xfffffe0007949fd0 / 0xfffffe000792ffc0 | 0xef / 0x61 / 0xeb2 / 0x0 | `0xfffffe000847a7b8` / `0xfffffe000c4ba154` |
| allocation_descriptor | 0xfffffe0007949dd0 / 0xfffffe000792fbc0 | 0xd8 / 0x20 / 0x7b / 0xfffffffffffffff8 | `0xfffffe00084723d8` / `0xfffffe000847bea0` |
| auxiliary_free | 0xfffffe0007941f60 / 0xfffffe000794a0d0 | 0x5 / 0x2d / 0xeed / 0x0 | `0xfffffe000847a7f0` / `0xfffffe000c4ba84c` |
| primary_free | 0xfffffe0007941f60 / 0xfffffe000794a0d0 | 0x5 / 0x2d / 0xeed / 0x0 | `0xfffffe000847a7f0` / `0xfffffe000c4ba84c` |
| context_free | 0xfffffe0007941f60 / 0xfffffe000794a0d0 | 0x6d / 0x13 / 0xf18 / 0x0 | `0xfffffe000847a878` / `0xfffffe000c4ba368` |
| context_descriptor | 0xfffffe0007949dd0 / 0xfffffe000792fbc0 | 0x73 / 0x47 / 0x88 / 0xfffffffffffffff4 | `0xfffffe0008472578` / `0xfffffe000847ba60` |
| workspace_free | 0xfffffe000792fdc0 / 0xfffffe00079392f0 | 0x93 / 0xec / 0xe39 / 0x0 | `0xfffffe000847a848` / `0xfffffe000c4b9a24` |
| container_free | 0xfffffe0007949ed0 / 0xfffffe000792fec0 | 0x92 / 0xa2 / 0xe89 / 0x0 | `0xfffffe000847a878` / `0xfffffe000c4ba368` |
| container_descriptor | 0xfffffe0007949ed0 / 0xfffffe000792fec0 | 0x92 / 0xa2 / -0x55 / 0xfffffffffffffffc | `0xfffffe0008472168` / `0xfffffe000847bde0` |
| node_free | 0xfffffe0007949fd0 / 0xfffffe000792ffc0 | 0x37 / 0x3a / 0xef1 / 0x0 | `0xfffffe000847a878` / `0xfffffe000c4ba368` |
| node_descriptor | 0xfffffe000792fcc0 / 0xfffffe00079391f0 | 0x47 / 0x7b / 0x149 / 0xfffffffffffffff8 | `0xfffffe0008472d20` / `0xfffffe000847be20` |
| data_free | 0xfffffe0007941f60 / 0xfffffe000794a0d0 | 0x6d / 0x13 / 0xf07 / 0x0 | `0xfffffe000847a7f0` / `0xfffffe000c4ba84c` |

| Private index | Original slot | Target |
| --- | --- | --- |
| 0x1a | `0xfffffe0008472ff0` | `0xfffffe000a665e90` |
| 0x204 | `0xfffffe0008473f40` | `0xfffffe000a6661bc` |
| 0x247 | `0xfffffe0008474158` | `0xfffffe000a660614` |
| 0x2b7 | `0xfffffe00084744d8` | `0xfffffe000a66229c` |
| 0x414 | `0xfffffe0008474fc0` | `0xfffffe000a660750` |
| 0x41e | `0xfffffe0008475010` | `0xfffffe000a660534` |
| 0x432 | `0xfffffe00084750b0` | `0xfffffe000a660614` |
| 0x480 | `0xfffffe0008475320` | `0xfffffe000a6604fc` |
| 0x49c | `0xfffffe0008475400` | `0xfffffe000a665e90` |
| 0x4a7 | `0xfffffe0008475458` | `0xfffffe000a656f4c` |
| 0x5aa | `0xfffffe0008475c70` | `0xfffffe000a665fc8` |
| 0x989 | `0xfffffe0008477b68` | `0xfffffe000a66066c` |
| 0x99e | `0xfffffe0008477c10` | `0xfffffe000a660790` |
| 0x9a7 | `0xfffffe0008477c58` | `0xfffffe000a660468` |
| 0xafb | `0xfffffe00084786f8` | `0xfffffe000a660614` |
| 0xafc | `0xfffffe0008478700` | `0xfffffe000a6604a4` |
| 0xb10 | `0xfffffe00084787a0` | `0xfffffe000a6661bc` |
| 0xb16 | `0xfffffe00084787d0` | `0xfffffe000a641d54` |
| 0xb1d | `0xfffffe0008478808` | `0xfffffe000a666118` |
| 0xb28 | `0xfffffe0008478860` | `0xfffffe000a66609c` |
| 0xd61 | `0xfffffe0008479a28` | `0xfffffe000a665f8c` |
| 0xd7a | `0xfffffe0008479af0` | `0xfffffe000a6660b4` |
| 0xd99 | `0xfffffe0008479be8` | `0xfffffe000a666118` |
| 0xee1 | `0xfffffe000847a628` | `0xfffffe000a665f8c` |
| 0xf03 | `0xfffffe000847a738` | `0xfffffe000a665ee4` |

Every bank rule is checked over all256 inputs, including original pointer metadata and explicit biases. These are internal bank/dispatch indices, not IOUserClient selectors or Mach message IDs. This increment establishes no new Mach right, endpoint or emission site. External contracts remain in [Mach ports](mach_ports_report.md), [interface ABI](interface_abi_report.md) and [investigation status](interface_investigation_status.md).

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CR-A1: Pinned images, original pointer/symbol/descriptor records and predecessor receipts | CR1-CR9 | Fresh dual-image/full-controller custody, original descriptor strings, frozen-query reconstruction and four altered-evidence equality controls |
| CR-A2: Selected C/S/F roots, phase tokens, bank roots and retained frame epochs | CR1-CR8 | Original root stores and outer-allocation retention range; recover every incoming path, alias and intervening frame writer |
| CR-A3: AArch64 register widths, shifts/comparisons and modeled memory semantics | CR1-CR9 | Arbitrary u64 argument/u32 count/status, exact widened sizes, all3,584 bank inputs and alternate retag transform |
| CR-A4: Valid separate context4,096 B, workspace16,384 B, frame and selected staging/caller storage; allocation requests alone do not prove native success/identity | CR1-CR8 | Original allocation/result aliases, descriptor comparison and source extent custody; bind actual native allocation identities and alignment/results separately |
| CR-A5: Valid stable H/J fields and finite stable successor chain; ordinary callees preserve surviving phase state | CR3, CR6-CR8 | Empty/nonempty/list-buffer cases, saved-successor proof, callee-saved register havoc and callback0x1a composition; establish native callee memory effects, aliases and locking |
| CR-A6: Stable accessible staged bytes, separate writable caller span, preserved size/status cells and nominal copy pointer guards | CR4-CR8 | Null/nonnull auxiliary, zero/nonzero N, every J in1..N, live-state preservation, exact bounds/rank and same-mask predecessor proof; inspect native alias/mutation epochs and auxiliary producer |
| CR-A7: Ordinary callee returns, selected FP/SP relation and equal guard for normal result; alternate incoming storage paths are not all composed | CR6-CR8 | Original guard save/reload, both guard edges, structural epilogue and null staging-result seam; establish native allocator/canary/PAC behavior and all remaining incoming phases |
| CR-A8: Complete command effects, native external count/status interpretation, ownership and successful daemon/provider correlation remain unknown | CR9 limits | Recover modifying command bodies and actual auxiliary producer; correlate one successful exchange with exact input/output bytes, counts, selector/message and object epochs |

## Bounded continuation and cost

| Impact | Evidence target | Contribution |
| --- | --- | --- |
| High | Original caller and daemon use of the in/out buffer | Bind decoded copy-back bytes and final status to actual cross-layer consumption |
| High | Second command and other writers of protected Z | Recover which processing results become visible through copy-back |
| High | Auxiliary C+0x3c0 / S+0xbe4 producer and its incoming phase | Establish allocation/extent identity for the optional independent data-retirement request |
| High | Native allocator/type-site behavior, aliases and synchronization | Validate actual lifetime effects behind emitted retirement requests |
| Medium | Original u64 length channel versus low32 staging count | Establish admissible external widths and surrounding size validation |
| Medium | Every early allocation and controller-return path | Extend this source composition beyond the selected normal cleanup and null-staging seam |
| Medium | Earlier proof subranges versus outer allocation-request extents | Keep minimum modeled accessible storage distinct from actual requested allocation sizes |

For k finite parsed nodes and N staged bytes, selected cleanup/copy-back takes O(k+N) source work and O(1) auxiliary state, excluding native callee costs. N=0 skips copy-back; otherwise the rank/live-state certificate establishes N reverse byte steps on the nominal valid-storage path. Extraction takes O(B+I+256R) time/space for pinned input bytes B, selected instructions I and bank rules R. Proof construction takes O(instruction instances+query DAG); SMT search is separate with30 s/query limits. Extents use bytes, count/status channels are u32, addresses/cursors/retained size codecs are u64 and the workspace alignment request is64 B. No native target, allocator, port endpoint or IDB is executed or modified.

## Quality gates

- **QG1**: Factual source/control/data/lifecycle/ABI claims require no normative conclusion.
- **QG2**: CR-A1-CR-A8 enumerate dependencies and falsification probes.
- **QG3**: Selected outer requests, caller callback0x1a, container/list/auxiliary cleanup, finite staged copy-back, retirement order, guard/status return and null-staging incoming seam are covered; the full objective remains active.
- **QG4**: Byte extents, low32 narrowing, exact u64 codec cancellation, pointer/status widths, alignment and O(k+N) cost are explicit.
- **QG5**: Staged/auxiliary/caller buffers, earlier modeled subranges/outer request sizes, descriptor metadata/site identity, raw/decoded status, phase/ownership and emitted requests/native effects remain distinct.
- **QG6**: Dual-image words, original pointers/symbols/descriptors, 44 nonvacuous source formulas, six predecessor rechecks, 3,584 bank cases, 76 structural instructions and four custody equality controls support bounded claims.
- **QG7**: Ranked continuation retains cross-layer in/out identity, modifying commands, auxiliary producer, native ownership/locking, count-width validation and remaining incoming paths.


## Selector26 transfer boundary

The recovered guarded raw-status decode and original size codec are rechecked and composed with the surrounding provider/handler. The provider preserves normal core X0 while requesting copy-out before cleanup/status propagation; the handler publishes12 descriptor bytes only on low32 success. Actual transfer and all controller incoming paths remain unproved. [Evidence and exact boundaries](userclient_transfer_boundary_report.md).
