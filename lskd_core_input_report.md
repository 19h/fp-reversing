# Selector18 input-shape successors, cleanup and status publication

The original `_zgcqcxw1qve0CY` rejection path now returns `0xFFFF5966` (signed32 -42650) after preparing typed-region and aligned-workspace cleanup. Seventy-four private executions complete that original epilogue under explicit register-only allocator/free returns. Twenty-four shape-selected executions instead stop before `IOMallocData(length32)` at0xfffffe000a56d228. No input-content read, accepted operation or native heap effect is established. [CI1-CI11]

The original UserClient continuation stores provider W0 at output+0xC14, and clears the u32 count at output+0x0C when W0 is nonzero. Five separate local cases reproduce these stores. Its later `W0=0` instruction is a distinct outer-method result, conditional on reaching it after descriptor release. Descriptor release, an actual Mach reply and daemon observation remain unknown. [CI8-CI9]

[Source contracts](triage_evidence/lskd_core_input_contracts.json), [retained core cases](triage_evidence/lskd_core_input_profiles.json), [fresh replays](triage_evidence/lskd_core_input_replays.json), [independent byte checks](triage_evidence/lskd_core_input_checks.json), [seven core source proof pairs](triage_evidence/lskd_core_input_proofs.json), [caller source/proofs/cases](triage_evidence/lskd_core_input_caller.json), [fresh caller checks](triage_evidence/lskd_core_input_caller_checks.json), [source identity](triage_evidence/lskd_core_input_source_identity.json), [preservation](triage_evidence/lskd_core_input_preservation.json) and [scoped gates](triage_evidence/lskd_core_input_quality_gates.json) retain the evidence. The broader objective remains active.

```text
original selector18 core -> address/length shape guard
  |
  +-- rejected -> IOFreeTypeImpl(view4096,auxiliary) [register return]
  |           -> IOFreeAligned(workspace,16384)    [register return]
  |           -> guard comparison / original epilogue
  |           -> W0=0xFFFF5966
  |                |
  |                +--> UserClient status+0xC14 / count+0x0C=0
  |                     [separate source-local composition]
  |                     -> descriptor release [unexecuted]
  |                     -> outer W0=0 [conditional source instruction]
  |
  +-- selected -> IOMallocData(length32) [stop before call]

no input-content bytes or native heap contents are supplied
```

All offsets are hexadecimal unless explicitly decimal. B denotes bytes. Status signedness is an interpretation of the same32-bit word; the symbolic error name is unknown.

## Assumption register

| ID | Assumption / bound | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| CI1 | Pinned KC and normalized kext identify this build | Source, imports, metadata and slots | Rehash originals; compare every retained source span and original chained pointer |
| CI2 | Declared private A64 semantics and abstract PAC | Private control/data results | Independently audit original instruction bytes, epochs and exact authenticated slots; native PAC remains unknown |
| CI3 | Two inherited allocators return distinct nonnull regions | Core continuation | Verify exact arguments, source-only initialization and register clobbers; native allocation/contents/lifetime remain unknown |
| CI4 | Two cleanup models return and preserve callee-saved registers | Completed rejection epilogues | Check exact targets/arguments and model epoch contains no memory access; native free effects remain unknown |
| CI5 | Original numeric guard and saved u32 length govern this branch | Selected/rejected partition | Preserve43 prior prefixes; test null address,15/16/65536/65537, zero and0xFFFFFFFF lengths across declared contexts |
| CI6 | Source bank cells retain the checked frame epochs | Four decoded interfaces | Check all six bank cells per case; exhaust256 inputs for each rule and verify original slots/diversities |
| CI7 | Source encoded status survives both cleanup returns in X21 | Return0xFFFF5966 | Prove all-word decode; verify source seed, all74 returns, restored GP registers and stack pointer |
| CI8 | UserClient receives provider/core W0 with output pointer in X19 | Embedded status/count composition | Recheck original provider chain and caller source; independently execute stores with five status fixtures; complete native parent path remains unknown |
| CI9 | Outer method reaches its separate W0=0 instruction after descriptor release | Outer-method return claim | Prove only that instruction; inspect descriptor release and actual transport separately; neither executes here |
| CI10 | WZR stack probes discard values; every other private value read requires initialized bytes | Source execution | Independently verify196 exact discard reads and all other private read epochs; unknown arena bytes stay masked |
| CI11 | Nonnull address and numeric length bounds do not validate content | Selected allocation frontier | Stop before IOMallocData; recover subsequent input reads/parser separately; no input fixture is supplied |

CI1-CI11 qualify dependent claims. The free models set X0 to a declared sentinel, clobber X1-X17 and NZCV, advance LR/PC, and perform no memory writes. Their X0 sentinel does not determine the source rejection result. Successful processing, native ownership and transport are not inferred from these models.

## Exact interfaces and source locations

| Source site | Resolved target / arguments | Evidence boundary |
| --- | --- | --- |
|0xfffffe000a594d14 |Shape dispatch: index0x4BB ->0xfffffe000a58c0bc;0x76A ->0xfffffe000a56d1b4 |Original branch traversed with abstract PAC |
|0xfffffe000a56d228 |`_IOMallocData` / `_IOMallocData_external`,0xfffffe000c4ba60c;X0=zero-extended length32 |Call remains unexecuted in24 cases |
|0xfffffe000a58c14c |`_IOFreeTypeImpl`,0xfffffe000c4ba368;X0=view0xfffffe000847aee0,X1=auxiliary |74 register-only cleanup returns |
|0xfffffe000a58c194 |`_IOFreeAligned`,0xfffffe000c4b9a24;X0=workspace,X1=16384 |74 register-only cleanup returns |
|0xfffffe000a58c1b8 |`W0 = W21 XOR 0x52982734` |Original rejection status decode |
|0xfffffe000a58c1ec |Original `RETAB` |74 private returns under abstract PAC |
|0xfffffe000a504780 |Store provider W0 to output+0xC14 |Five separate source-local caller cases |
|0xfffffe000a504784 /0xfffffe000a504788 |CBZ W0 skips count clear for zero; otherwise store0 at output+0x0C |Four nonzero status fixtures clear the count |
|0xfffffe000a5047a8 |Descriptor-release virtual call |Unexecuted architectural boundary |
|0xfffffe000a5047bc |Set outer method W0=0 |Source-local proof; complete caller/transport unexecuted |

The source argument move at0xfffffe000a56d208 is `MOV W0,W13`; it establishes zero extension into X0. Stores0xfffffe000a56d21c/220 save that length at SP+0x4F8 and the typed pointer at SP+0xD40. X1 is residual state at the IOMallocData frontier, not evidence of an additional input parameter.

The retained original IOMallocData function saves its size, prepares a kernel allocator delegate and performs accounting conditionally after a nonnull result. That native body is read back without execution. No assumption about zero initialization follows from its name. The post-call source store at0xfffffe000a56d238 would place X0 at typed+0x60 under the saved-pointer premise; it remains unexecuted in every case here.

## Exhaustive bank and pointer provenance

| Role | Byte key / constant / additive | Index / original slot | Target / source bias |
| --- | --- | --- | --- |
|Input allocation |0xEA /0x22 /+0x9C8 |0x9EA /0xfffffe0008471370 |0xfffffe000c4ba60c;diversity0x3FC0 |
|Typed cleanup |0xAA /0xA4 /+0x967 |0xA0B /0xfffffe0008471478 |0xfffffe000c4ba368;diversity0x560F |
|Cleanup view |0x65 /0xF4 /-0xDC |0x18 /0xfffffe00084717a0 |Original pointer0xfffffe000847aee4, then source subtracts4 |
|Aligned cleanup |0x3B /0xCA /+0x92D |0x9F7 /0xfffffe00084713d8 |0xfffffe000c4b9a24;diversity0xB389 |

Each bank rule is exhaustively checked over256 byte inputs. Original format8 chain membership and authentication/diversity fields are retained. These internal indices and modifiers are not Mach message IDs or rights.

The cleanup view0xfffffe000847aee0 differs from allocation view0xfffffe000847ae20. Both file records name `site.AllocType`, carry flags0xE4 and size4096 B, and refer to the same two metadata addresses. Distinct site records with matching declared type/size do not prove equality of native runtime links. Those links and actual heap identity remain unknown. The source passes the original modeled auxiliary pointer to cleanup.

Original `_IOFreeTypeImpl` tail-calls `_kfree_type_impl` at0xfffffe000bcff010. Its file-cold path reads flags/size at view+0x28/+0x2C and masks size to24 bits. Original `_IOFreeAligned` rearranges workspace/size into X1/X2 and tail-calls0xfffffe000c4b9898. Exact symbols for0xfffffe000c4b9898 and the IOMallocData delegate0xfffffe000bcfe5b8 are unknown; they are not assigned inferred public names.

## Status, frame and byte provenance

The original guard sets X16=0xAD677E52 at0xfffffe000a594cf8/fc. The rejection fragment copies it to callee-saved X21 before either cleanup call. Source decode then gives:

```text
u32(0xAD677E52 XOR 0x52982734) =0xFFFF5966
signed32 =4294924646 -4294967296 =-42650
```

The all-word source lemma proves `return32 = low32(encoded64) XOR 0x52982734`; the fixed source seed establishes this path's concrete status. It is a core business status, distinct from the outer UserClient return register.

All74 rejection cases preserve equal saved/global guard values, restore X19-X29, restore LR and return SP to entry SP. The source epilogue reclaims0x13C0 B, then its final vector load reclaims the0xA0 B save area:0x13C0+0xA0=0x1460=5216 B. Native authentication and guard mismatch behavior are untested. No mismatch is induced.

No source write occurs after the guard on the rejected path. Each selected path adds only the two saved-argument stores described above. The workspace still has16 source-initialized bytes, and the4096-byte auxiliary region has none. There are no work-region value reads or input/output-buffer accesses in all98 core cases. The two selected-pointer lengths are16 and65536 B across entry kinds, controller fixtures and frame placements; the pointer backing remains unknown and unread.

In the separate caller cases, an initially unknown count remains unknown for status0; no zero is invented. The four nonzero status fixtures cause an actual source store of zero. Only0xFFFF5966 is derived from this core path; the other caller statuses are isolated branch controls. The caller cases stop at0xfffffe000a50478c before loading the descriptor vtable.

## Verification and preservation

| Item | Verified value |
| --- | --- |
|Original KC SHA-256 |`d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
|Normalized kext SHA-256 |`2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
|Fresh core cases / exact preceding prefixes |98 /43 |
|Original core instruction visits / byte checks |1351240 /5404960 B |
|Read / write epochs |116588 /126272 |
|Register-only model returns / model memory writes |344 /0 |
|Original rejection returns / selected allocation frontiers |74 /24 |
|Checked cleanup models / restored callee-saved GP registers |148 /814 |
|Core proof pairs / lifted instruction instances |7 /20 |
|Original native function readbacks / cleanup metadata |4 /64 B |
|Exhaustive bank rules / byte inputs |4 /1024 |
|Separate caller cases / source visits / source data reads |5 /14 /0 |
|Caller proof pairs / lifted instruction instances |3 /3 |

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_lskd_core_input.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_lskd_core_input.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_lskd_core_input.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_core_input.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/lskd_core_input_caller.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_core_input_caller.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_core_input_preservation.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_core_input_delivery.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_sidecar_delivery.py
```

Run producer and verifier commands sequentially and wait for terminal completion. A preliminary verification rejected a stale generator hash while regeneration was still pending; accepted checks were generated only after producer termination and a fresh successful verification. No partial or stale attempt is counted.

The baseline contains2159 artifacts:2153 remain unchanged with six declared report/index edits. Original analysis.md, C and calls inputs remain unchanged. Retained time/space is O(B+C*(V+E)+I+256R), plus solver cost (30 s/query), where B is source bytes,C cases,V source visits,E byte-event extents,I inspected/lifted instructions and R bank rules. The separate caller execution has at most3 instructions per case. Source-local symbolic claims and finite private executions retain distinct scopes.

## Remaining interfaces and bounded opportunities

| Impact | Further investigation | Required evidence |
| --- | --- | --- |
|High |Recover subsequent input-content consumers |Original source following nonnull IOMallocData; preserve unknown allocation/input bytes and stop at unmodeled operations |
|High |Establish daemon-side selector18 caller and error handling |Exact packet/connection and consumer of embedded status versus outer return |
|High |Connect successful core entry to actual tag/vector publication |Reaching definitions and source stores, without inventing accepted context state |
|Medium |Establish native typed/allocation ownership |Runtime view links, allocator initialization, deallocation and synchronization evidence |
|Medium |Complete UserClient descriptor-release/transport composition |Exact vtable target, lifetime and emitted Mach reply/right evidence |

No additional incoming/outgoing Mach port, message ID, right transfer or emission is established in this increment. The status distinction identifies a caller-observation boundary; it is not evidence that an actual reply was emitted. The full investigation remains active.

| Gate | Scoped disposition | Evidence |
| --- | --- | --- |
|QG1 |Pass |Factual source/interface analysis |
|QG2 |Pass |CI1-CI11 list dependencies and falsification probes |
|QG3 |Pass for increment |Guard successors, cleanup, status and caller publication covered; broad objective incomplete |
|QG4 |Pass |Exact widths/extents, status arithmetic, counts and sequential reproduction |
|QG5 |Pass |Shape/content, private/native heap, status layers, source/unknown bytes and caller composition separated |
|QG6 |Pass |98 fresh core audits,43 exact prefixes,5 fresh caller cases,10 source proof pairs and original fixup/native readbacks |
|QG7 |Pass |Impact-labeled continuation table |
