# Selector18 core work regions, frame initialization and numeric input guard

The actual `_zgcqcxw1qve0CY` entry now continues through two register-only allocator-return models, two original unsigned-ordering calls,136 source frame-pointer stores and a1096-byte source scratch-clear loop. It then selects a source fragment using the saved input address and u32 length. No input-content parser, complete operation, native allocation or Mach exchange executes. [CW1-CW11]

The numeric predicate is `input_address != 0 && 16 <= length32 && length32 <= 65536`. This is a shape predicate; selected input content and native buffer validity remain unknown. The new proof explicitly models CCMP NE's unsigned carry, including its fallback NZCV value. Forty-three fresh cases reach the selected-fragment boundary, with2 shape-selected and41 rejected cases. All36 preceding entry prefixes remain identical.

[Source contracts and complete pointer catalog](triage_evidence/lskd_core_workspace_contracts.json), [retained cases](triage_evidence/lskd_core_workspace_profiles.json), [fresh replays](triage_evidence/lskd_core_workspace_replays.json), [independent byte checks](triage_evidence/lskd_core_workspace_checks.json), [eight source proof pairs](triage_evidence/lskd_core_workspace_proofs.json), [source identity](triage_evidence/lskd_core_workspace_source_identity.json), [preservation](triage_evidence/lskd_core_workspace_preservation.json) and [scoped gates](triage_evidence/lskd_core_workspace_quality_gates.json) retain the evidence. The broader investigation remains active.

```text
selector18 -> provider -> original core entry
  -> IOMallocAligned(16384 B,64 B) [register return only]
  -> IOMallocTypeImpl(site.AllocType,declared4096 B) [register return only]
  -> original unsigned-order checks
  -> source frame-pointer catalog and16 source workspace bytes
  -> source clears frame[F68..13AF],1096 bytes
  -> input address/length shape guard
       selected -> A56D1B4 [unexecuted]
       rejected -> A58C0BC [unexecuted]

no allocator memory contents or input bytes are supplied
```

## Assumption register

| ID | Assumption / bound | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| CW1 | Pinned KC and normalized kext identify this build | Source bytes, symbols, views and slots | Rehash and compare original windows/fixups; native allocator code is read from the KC |
| CW2 | Private A64 semantics and abstract PAC match the declared model | Guest/source outcomes | Check each byte/read/write and original target slot; native PAC remains unknown |
| CW3 | Two allocator models return distinct, nonnull work regions and caller-clobbered registers | Continued source flow | Verify exact targets/arguments and no model memory writes; native success, contents and lifetime remain unknown |
| CW4 | Work-region fixture extents are16384 and4096 bytes | Concrete alias/address checks | Check source requests/type-view metadata and all accesses; these are not observed native allocations |
| CW5 | Source-defined frame cells and fixed symbolic cells retain declared aliases | Pointer/store lemmas | Reconstruct every write epoch; check all136 final frame cells in43 cases |
| CW6 | Original ordering helper tests unsigned X0<=X1 | Two ordering interfaces | Recheck original body and86 actual private calls; it establishes ordering, not allocation/accessibility |
| CW7 | Scratch-loop phase starts X8=0,W12=0x4CD | Exact clear extent and termination | Prove initialization/step, check no intervening X8 definition, verify every byte store and final target |
| CW8 | Input length is the saved u32 word; address is the saved u64 | Numeric input guard | Source-lift CCMP carry/fallback and all u32 lengths; test min/max, adjacent lengths and null address |
| CW9 | Shape selection does not establish content/native validity | Parser frontier | Inspect subsequent input reads and native buffer provenance separately; no input bytes are initialized here |
| CW10 | WZR stack probes discard values | Earlier prefix continuation | Verify exact probe PCs/destination and known-byte checks for all other private reads |
| CW11 | Typed-view runtime links/native heap state are unknown | Native allocator boundary | Compare original64-byte metadata and two native allocator functions; recover runtime cache/ownership separately |

CW1-CW11 qualify dependent claims. Source performs every observed memory write; models change registers/PC/flags only. No uninitialized private value is consumed.

## Primary provenance and verification

| Item | Verified value |
| --- | --- |
| Original KC SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| New kext spans / original native allocator functions |4 /2 |
| Fresh cases / exact preceding prefixes |43 /36 |
| Original instruction visits / byte checks |590018 /2360072 bytes |
| Read / write epochs |49751 /55384 |
| Register-only allocator models / model memory writes |86 /0 |
| Original ordering calls / frame-pointer store pairs |86 /5848 |
| Scratch byte stores / loop authenticated edges |47128 /47128 |
| Guard cells preserved through clear |43 |
| Source proofs / lifted instruction instances |8 /328 |
| Exhaustive bank rules / byte inputs |4 /1024 |

## Allocation and ordering interfaces

| Source call | Target / argument | Evidence boundary |
| --- | --- | --- |
|0xfffffe000a5304c8 |`_IOMallocAligned` at0xfffffe000c4b9a08;16384 bytes,alignment64 | Model returns private workspace0x6300008000; native target unexecuted |
|0xfffffe000a530564 |`_IOMallocTypeImpl` at0xfffffe000c4ba154;view0xfffffe000847ae20 | Model returns private typed region0x630000c000; native target unexecuted |
|0xfffffe000a5305d0 |Ordering helper0xfffffe000a561058;workspace+0xD00,workspace+0x4000 | Original comparison/return executes |
|0xfffffe000a530630 |Same helper;typed+0x400,typed+0x1000 | Original comparison/return executes |

Original typed-view metadata names `site.AllocType`, flags0xE4 and size4096. Its first16 runtime-link bytes are zero in the file; their native values remain unknown. The original `_IOMallocTypeImpl` wrapper reads flags at+0x28 and tail-calls `_kalloc_type_impl` at0xfffffe000bcfeb8c. That native delegate's file-cold path reads the flags/size pair at+0x28/+0x2C. Both complete original native functions are retained without execution. Actual native heap behavior and initialized contents are not inferred from file metadata.

The declared work regions are adjacent and disjoint in the private fixture. Caller-saved GP registers and flags are clobbered by each model. The source then recovers its operands and performs all stores itself. No model initializes an arena or object. [CW3-CW4, CW11]

## Frame-pointer catalog and source-defined bytes

The contract file contains136 exact ADD/STR source pairs:108 workspace-derived pointers and28 typed-region pointers. Each row records original bytes, ADD/store PCs, base register, region offset and frame offset. All136 source stores and final values are checked in each case. Their symbolic lemma covers arbitrary declared region bases under the fixed-cell premises.

| Saved frame cell | Source value / use |
| --- | --- |
|SP+0x7F8 |workspace+0xD00 ordering-start pointer |
|SP+0x7F0 |workspace+0x4000 ordering-end pointer |
|SP+0x800 |typed+0x400 ordering-start pointer |
|SP+0x7E8 |typed+0x1000 ordering-end pointer |
|SP+0xD50 |Workspace base |
|SP+0xD90 |Workspace+0x4E0 after source store0xfffffe000a530914 |

SP+0xD90 earlier holds the dispatch-table pointer+8, which is read at0xfffffe000a530748 before its later workspace-pointer store. Frame meanings therefore depend on source epochs; the pointer catalog describes the post-initialization epoch.

Only16 workspace bytes are initialized by this checked source prefix:

| Workspace offset | Width | Source value | Store PC |
| --- | --- | --- | --- |
|+0x638 |8 bytes |0x908B69373110A675 |0xfffffe000a530734 |
|+0x25C |4 bytes |0x13F6F63F |0xfffffe000a530740 |
|+0x160 |4 bytes |0x13F6F63F |0xfffffe000a530744 |

All other workspace bytes and all4096 typed-region bytes retain unknown-byte masks. No work-region value is read before the current boundary. Those untouched bytes are not promoted to zero or native allocator output.

## Exact frame-scratch clear

Source0xfffffe000a530638 sets X8=0; subsequent initializer instructions preserve it. The original loop at0xfffffe000a56d11c stores zero at frame+0xF68+X8, compares the old counter with0x447 and increments it. Index0x4CD repeats the loop;0x4D2 exits to0xfffffe000a594c70. Both original authenticated slots have diversity0x97F6.

The inclusive byte count is0x447-0+1=0x448=1096. The cleared interval is `[frame+0xF68,frame+0x13B0)`. Its exclusive end equals the saved stack-guard cell's address. Independent epochs verify that each byte is written exactly once by the loop, all receive source provenance and the guard cell receives no loop write. Subsequent source clears within that interval do not extend it. This is frame-scratch initialization, not clearing either work region.

## Numeric input guard and control boundary

Source0xfffffe000a594cb0 reads the saved length at SP+0xAE4;0xfffffe000a594cb8 reads the saved address at SP+0xAD8. The source computes `u32(length-16)`, compares it with0xFFF1 when the address is nonzero and otherwise installs NZCV=2. Its carry bit rejects the null-address case. Thus the source predicate is:

```text
address64 != 0 AND unsigned32(length32 -16) <65521
equivalently: address64 != 0 AND 16 <= length32 <=65536
```

| Shape result | Source index / target | Current evidence |
| --- | --- | --- |
| Selected |0x76A ->0xfffffe000a56d1b4 |Two end-to-end private prefixes: lengths16 and65536 |
| Rejected |0x4BB ->0xfffffe000a58c0bc |41 private prefixes, including adjacent lengths and null address |

All cases stop before branch0xfffffe000a594d14 executes. No instruction in either selected fragment executes. The accepted/rejected labels refer only to this numeric predicate. Input bytes, message format, output contents, whole-operation status and native validity remain unknown.

No additional incoming/outgoing Mach port, right transfer, message ID or emission is established. The checked interfaces are allocator preparation, internal work regions, frame scratch and a local input guard within selector18's kernel core.

## Reproduction and preservation

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_lskd_core_workspace.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_lskd_core_workspace.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_lskd_core_workspace.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_core_workspace.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_core_workspace_preservation.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_core_workspace_delivery.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_sidecar_delivery.py
```

The baseline contains2125 artifacts,2119 unchanged with six declared report/index edits. Original analysis.md, C and calls inputs remain unchanged. Time and retained space are O(B+C*(V+E)+I+256R), plus solver cost (30 s/query); B denotes source bytes,C cases,V visits,E byte-event extents,I lifted/inspected instructions and R bank rules. The loop has exactly1096 iterations per case.

| Impact | Further investigation | Required evidence |
| --- | --- | --- |
| High | Recover selected/rejected guard fragments | Original source and subsequent reads/status/cleanup; preserve unknown private/input bytes |
| High | Connect entry to actual tag/vector writers | Source predecessor/reaching-definition path and publication stores |
| High | Establish native heap and synchronization contracts | Runtime allocation/initialization, lock identity, ownership and reclamation |
| Medium | Recover work-region field meanings | Full consumers of the136 frame aliases and16 source seed bytes |
| Medium | Establish daemon-side selector18 correspondence | Exact caller, packet, endpoint and port/right evidence |

| Gate | Scoped disposition | Evidence |
| --- | --- | --- |
| QG1 | Pass | Factual source/interface analysis |
| QG2 | Pass | CW1-CW11 identify dependencies and falsification probes |
| QG3 | Pass for increment | Work/frame/clear/shape interfaces covered; broad objective incomplete |
| QG4 | Pass | Exact widths, extents, calculations, counts and reproduction |
| QG5 | Pass | Models/native effects, ordering/allocation bounds, initialized/unknown bytes and shape/content validation separated |
| QG6 | Pass |43 fresh byte audits,36 exact prefixes, eight source proofs, metadata/fixups and complete native allocator readbacks |
| QG7 | Pass | Impact-labeled continuation table |
