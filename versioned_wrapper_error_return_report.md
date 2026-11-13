# Selector-21 wrapper return and UserClient error-result fields

Subsequent source extension: The [daemon IOKit-result report](daemon_iokit_result_report.md) consumes the produced 0xffff5a5e word only as a separately declared output+0x224 compatibility control. With independently declared API status zero, the daemon encodes that field to 0x74c29c0f and reaches source cleanup/root publication. This does not establish native IOKit success, output-buffer identity or a paired daemon-kext transaction.

The retained provider-absent selector-21 path now completes the dispatcher and `_UeFdbi` wrapper in the source model. The wrapper copies count 512 to its caller's mutable count cell, requests auxiliary and workspace frees, translates raw workspace status `0xce515a38` to `0xffff5a5e`, and restores its entry SP and X19-X29. A separate original UserClient suffix, supplied that actual source-produced nonzero return, stores it at output+`0x224`, skips the count store at output+`0x220`, and sets W0 to zero. Native API completion, output-buffer identity and daemon-kext transaction pairing remain unknown. [WR1-WR7]

```text
preceding provider-absent release + three declared free returns
  -> dispatcher W+0 = 0xce515a38
  -> original dispatcher epilogue -> original wrapper continuation
  -> W19 = W[0]; *Q = wrapper-local count = 512
  -> pending typed free(auxiliary A)
       separate ordinary void return + logical A retirement
  -> pending _IOFreeAligned(workspace W, 16384 B)
       separate ordinary void return + logical W retirement
  -> W0 = 0xce515a38 XOR 0x31ae0066 = 0xffff5a5e
  -> restored wrapper frame -> declared caller boundary

separate UserClient source component; valid post-provider ABI premise
  supplied provider W0 = 0xffff5a5e
  -> output[0x224:0x228] = 5e 5a ff ff
  -> CBNZ skips output+0x220 count store
  -> method W0 = 0
  native IOKit transport/copyout and daemon observation: unknown
```

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| WR-A1 | Pinned original images and exact parent receipts identify this build and reaching source epoch. All new continuations depend on them. | Rehash dependencies, reproduce every retained parent prefix and compare every source word with original KC and normalized kext bytes. Native task/build/provider pairing remains unknown. |
| WR-A2 | The preceding distinct allocations, finite global/controller fixtures, declared cold matching/wait returns, absent provider and NULL/NULL release route remain in force. This error path depends on them. | Reproduce the parent hardware and cleanup intervals exactly; retain symbolic/unspecified bytes and supply no allocator fill. Other modes, warm providers and concurrent state are outside this path. |
| WR-A3 | Original wrapper prologue stores, the original dispatcher call and retained live frame bytes compose with the dispatcher epilogue. Return continuity depends on this join. | Check the actual prior call, preceding pointer read, original format-8 authenticated slot, return PC, SP and saved-register bytes. The root wrapper entry/return sentinel is an explicit model premise; no native caller identity is inferred. |
| WR-A4 | Each pending free is followed separately by an ordinary void return preserving callee-saved state/SP, clobbering X0-X18 and making no model memory writes. Later wrapper behavior depends on those premises. | Retain both original pending calls and exact arguments; provide no scalar success result. Native allocation ownership, destruction, faults, waiting and concurrent effects remain unknown. |
| WR-A5 | Retirement is analysis bookkeeping; source reads/writes must avoid retired spans. Access and ordering results depend on that rule. | Independently reject every source read/write intersecting H3/H2/H1/A/W after the respective declared free return. Evidence snapshots are analyst reads and do not assert target liveness. |
| WR-A6 | Source equations use valid, distinct source-cell/frame contracts and u32/u64 register semantics. Algebra and finite count propagation depend on them. | Re-run three UNSAT queries with satisfiable premises and audit actual byte addresses in all eight cases. The symbolic cell model does not prove arbitrary aliasing, invalid-address behavior, PAC execution or concurrency. |
| WR-A7 | The separate UserClient component starts after a normally returning provider call with valid output/ABI state and the produced nonzero scalar. Its result-field mapping depends on this premise. | Check original STR/CBNZ/MOV encodings, branch width/target and separate count/status fields. Do not manufacture a receiver, output pointer, native transport return or daemon buffer join. |

## Dispatcher return, count copy and wrapper cleanup

The [preceding release report](versioned_error_release_report.md) ends before `0xfffffe000a5a729c`. The new source lift executes that epilogue, restores the 608 B dispatcher frame and returns at `0xfffffe000a5a72b8` to `0xfffffe000a5a2f54`. Its call-frame join uses the actual preceding wrapper call `0xfffffe000a5a2f50`, target `0xfffffe000a5a5470`, SP and pointer read `0xfffffe000a5a2f44`. Original slot `0xfffffe000847a9e8` is authenticated IA with diversity `0x1e46`. Reconstructing this logical call record does not re-execute the earlier call or establish native PAC behavior. [WR2-WR4,WR7]

The wrapper has a separate 256 B frame. Original instructions establish: [WR3-WR5]

| Original instruction PC | Source effect |
| --- | --- |
| `0xfffffe000a5a2f54` | Latch workspace W+0 into W19 before workspace retirement. |
| `0xfffffe000a5a2f58` | Read the wrapper-local u32 count at wrapper SP+`0x88`. |
| `0xfffffe000a5a2f5c` | Store that u32 to mutable count pointer Q, including this error path. |
| `0xfffffe000a5a3034` .. `0xfffffe000a5a303c` | Construct `0x31ae0066` and XOR it with latched W19 into W0. |
| `0xfffffe000a5a3040` .. `0xfffffe000a5a305c` | Restore saved registers/SP and return to the declared wrapper caller. |

All eight retained cases have count 512. The new continuation makes exactly one 4 B source write per case: `*Q = 512`. It does not define a new payload length, prove successful processing or establish a native API size result. The source equation proves copyback of an arbitrary local u32 COUNT under the stated cell contracts; finite reaching cases supply COUNT=512. [WR3-WR5,WR7]

| Order after the preceding three frees | Pending original call | Original target / exact symbol | Arguments / retained extent |
| --- | --- | --- | --- |
| Auxiliary free request | `0xfffffe000a5a2fe4` | `0xfffffe000c4ba368`, `_IOFreeTypeImpl` | X0=`0xfffffe000847ba60`; X1=A, preceding 4,096 B auxiliary object. |
| Workspace free request | `0xfffffe000a5a3030` | `0xfffffe000c4b9a24`, `_IOFreeAligned` | X0=W; X1=16,384 B. |

The first pending edge uses original slot `0xfffffe000847a878`, IA diversity `0x4d6a`; the second uses `0xfffffe000847a848`, IA diversity `0x84ff`. The workspace target's exact original kernel symbol is `_IOFreeAligned`; its complete original compiler function and symbol entry are retained. Native free bodies remain unexecuted. [WR3-WR4,WR6-WR7]

Separate ordinary void-return premises add A then W to the preceding H3/H2/H1 logical retired spans. No new source access intersects any retired span. The wrapper consumes its status from saved W19, without rereading retired W. The auxiliary field A+`0x270` and its previously published H3 address remain evidence snapshots; this continuation does not dereference that pointer or establish a native invalid access. [WR2-WR4,WR7]

The original prologue's actual saved bytes independently match final X19-X29 in each case: `8*11=88` register comparisons. Both dispatcher and wrapper source returns restore their respective call-entry SP: 16 return records across eight cases. The final wrapper SP equals its original entry SP. X0-X18 remain ordinary caller-clobbered registers except values explicitly redefined by source. [WR3-WR4,WR7]

## Four distinct result/count channels

All status arithmetic below is u32. The wrapper performs the exact bitwise translation: [WR3-WR5]

```text
raw dispatcher workspace word = 0xce515a38
wrapper return word = raw word XOR 0x31ae0066 = 0xffff5a5e
```

No recovered business status name is assigned to either word. Equal raw output from another failure path does not prove equal failure causes. The captured 13-instruction provider adapter at `0xfffffe000a504ea0` ends in a direct tail branch at `0xfffffe000a504ed0` to `_UeFdbi`; it has no post-core result translation. Its nominal selector-21 relationship is documented in the [request ABI report](versioned_request_abi_report.md). Actual virtual receiver, call admission and native return pairing remain unknown. [WR3-WR6]

| Channel | Value / exact source behavior | Evidence boundary |
| --- | --- | --- |
| Core wrapper W0 | `0xffff5a5e` | Produced by the continuous core source continuation under declared external-return premises. |
| Mutable core count `*Q` | 512 | Original error-path copyback at `0xfffffe000a5a2f5c`; local cell is wrapper SP+`0x88`. |
| UserClient embedded status, output+`0x224` | Store `0xffff5a5e` at `0xfffffe000a5050a0`. | Separate source suffix consumes the produced scalar under WR-A7. |
| UserClient count, output+`0x220` | No store by this error suffix. | Nonzero W0 branches at `0xfffffe000a5050a4` over count load/store `0xfffffe000a5050a8`/`0xfffffe000a5050ac`. Its post-provider bytes are preserved by this suffix. |
| UserClient method W0 | Zero, defined at `0xfffffe000a5050b0`. | Source method result definition; actual IOKit API/transport result remains unknown. |

The count-preservation statement starts after provider return. It does not assert that the field equals its original request value or that no earlier alias changed it. A 512 B core capacity/count, a 552 B structure contract, output+`0x220`'s u32 count and output+`0x224`'s u32 status have distinct roles. Highest shown status byte ends at offset `0x228=552 B`. No source or native output-buffer identity is invented to join these separate components. [WR3-WR5,WR7]

## Provenance and verification

| ID | Primary evidence |
| --- | --- |
| WR1 | Original KC SHA256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized kext `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. |
| WR2 | Preceding release receipt SHA256 `f1776efe92cb22fe7f829ea4764407864bfc0fb779e4a7b2b1e1b6e64f3bcedd`; exact fresh reaching-prefix/interval equality precedes the new continuation. Original wrapper prologue/call evidence comes from the pinned preparation receipt. |
| WR3 | [Extractor/source lift](triage_evidence/recover_versioned_wrapper_error_return.py): reconstructed original call/frame provenance, original epilogues, pending frees, separately declared void returns, translated scalar and separate UserClient suffix. |
| WR4 | [Compressed receipt](triage_evidence/versioned_wrapper_error_return_checks.json.zst): eight parent cases / 24 new core intervals, 584 source visits, 1,968 read bytes, 32 write bytes and 16 source returns; eight separate 3-instruction UserClient components. |
| WR5 | Three nonvacuous UNSAT source equations: status latch/count copy, XOR translation, and nonzero UserClient result/count fields. Eight data instructions are lifted; one original CBNZ is separately checked for register width and target. |
| WR6 | Fresh original complete wrapper, UserClient and 13-instruction provider-adapter captures; workspace-free kernel compiler function and exact `_IOFreeAligned` symbol. Original pointer chains bind both pending frees and the preceding dispatcher call. |
| WR7 | [Publication verifier](triage_evidence/verify_versioned_wrapper_error_return_publication.py): fresh extraction, independent reaching byte epochs and retired-span guards, count snapshots, original call joins, pending-free arguments, saved-register comparisons, result component, source queries, exact manifest delta and decoded-path hygiene. No native API, new guest execution or IDA mutation is performed; associated files suffice. |

The three intervals per parent contain 44, 18 and 11 source visits: `8*(44+18+11)=584`. Separate UserClient components add `8*3=24` inspected source words and are excluded from the continuous core count. Earlier reproduced prefixes are also excluded. The independent core byte audit checks 584 original source words, 1,968 read bytes and 32 write bytes; it separately checks eight prior call joins, 16 pending-free pointer joins and 88 restored registers. Original saved-frame reads are checked against their preceding byte definitions. There are no newly executed authenticated transfers: both free calls remain pending, and the earlier dispatcher call is joined from frozen evidence. [WR4,WR7]

Extraction/audit take O(receipt bytes+C*V+I+Q) time/space plus solver cost capped at 30 s/query. Each core interval is bounded at 10,000 steps. Large JSON and the manifest are losslessly roundtripped zstd level-22 archives. No new Mach message, port/right operation, input/output-B payload write or native daemon-kext transaction is established. [WR3-WR4,WR7]

| Impact | Further bounded work | Evidence needed |
| --- | --- | --- |
| High | Establish the complete native result path. | Matched build/task/connection/receiver, provider return, IOKit transport/copyout, output identity and daemon result consumer in one epoch. Source zero method status alone does not establish API success. |
| High | Establish auxiliary A+`0x270`'s full lifetime contract. | Matching-epoch publishers, replacements, consumers, dereference guards and actual allocation/free behavior. |
| High | Continue the warm/provider-present processing route. | Defined parameter-copy effects, provider/descriptor/buffer coherence, readiness state and actual provider operation; this error return does not establish successful processing. |
| Medium | Recover status-collapse and count-update equivalence classes. | Other original status producers and complete translation/caller recognition. Keep core count copyback separate from the UserClient success-only count field store. |
| Medium | Refine allocator bookkeeping interfaces. | Original callers, size/type-view contracts and native metadata effects for the two exact kernel targets; neither free's ownership effect is established here. |

- **QG1**: Pass. Factual source/ABI/control/data-flow analysis requires no normative content.
- **QG2**: Pass. WR-A1..WR-A7 state assumptions, dependent results and falsification probes.
- **QG3**: Pass for this increment. Dispatcher/wrapper return, both remaining cleanup requests, count/status translation and the separate UserClient result fields are covered. The full goal remains active.
- **QG4**: Pass. u32/u64 semantics, 608/256 B frames, 4,096/16,384 B spans, 512/552 B roles, field offsets and retained/reproduced counts are explicit.
- **QG5**: Pass. Continuous core source and separate UserClient suffix, pending calls and declared returns, exact symbol identity, logical/native retirement, embedded/method/API statuses and local/output counts remain distinct.
- **QG6**: Pass. Original bytes/fixups/symbols, pinned parents, nonvacuous source equations and independent byte/frame/result/publication checks supply scoped provenance.
- **QG7**: Pass. Native completion, auxiliary lifetime, warm processing, status/count classes and allocator interfaces are bounded and impact-ranked above.
