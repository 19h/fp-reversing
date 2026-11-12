# CoreFP1201 parent status gate and retained-result serialization

The original parent can carry the previously produced 128-byte export into the request1201 builder without modifying that buffer. This increment establishes the link through explicitly bound private parent re-entry, starting after the completed helper at `0x8f3564`. Twenty-one cases reach `0x8db0`, immediately before `_mig_get_reply_port`, with all 128 payload bytes and the scalar staged by original builder instructions. No API return, reply port, transport result or arithmetic output is supplied. Whole-parent native reachability and daemon/kext endpoint identity remain unknown.

## Primary evidence and assumption register

The [producer](triage_evidence/recover_fpsd1201_handoff.py), [original-byte journals](triage_evidence/fpsd1201_handoff_checks.json), [independent auditor](triage_evidence/audit_fpsd1201_handoff.py), [replay receipt](triage_evidence/fpsd1201_handoff_audit.json) and [publication verifier](triage_evidence/verify_fpsd1201_handoff_publication.py) retain the bounded evidence. Logical JSON links resolve to compressed `.json.zst` artifacts. The [export report](fpsd1201_export_report.md) supplies the completed helper checkpoints, while the [caller report](fpsd1201_caller_report.md) supplies the complete parent bytes and earlier conditional owner/port layout. Existing reference evidence is sufficient; no new IDA read or IDB edit is required.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| HF1 | The pinned original image identifies the parent, builder, lookup banks and pointer rows. All address claims depend on this image. | Independently parse the universal image and selected slice; compare all 86380 selected bytes and 79512 original fixup words. Reject any mismatch. |
| HF2 | Authenticated rebases use the original IA diversity and address diversity 0 under an explicit private PAC model. Control-flow conclusions depend on it. | Check source table loads, complete pre-branch frames, original raw words and all 3036 PAC records. Native PAC acceptance remains unknown. |
| HF3 | The earlier independently audited terminal CPU/RAM states establish the retained helper outputs. Prefix execution is not repeated. | Pin the exact export checks and audit hashes, original generator/auditor identities, complete restored CPU state and every restored RAM byte. Never patch the candidate output. |
| HF4 | Missing parent cells and two registers are explicitly declared bindings, not recovered native state. Re-entry and owner associations depend on them. | Retain before/after bytes for every binding; independently reconstruct them; prove output/context bytes unchanged. Trace actual upstream producers and frame epochs to remove this assumption. |
| HF5 | The retained wrapper adjustment is zero and the selected register state survives the helper. The local parent stack join depends on it. | Check SP, FP, W20, W22, W23, the adjustment cell, marker address and all source stores. Earlier parent epochs remain unjoined. |
| HF6 | NDR and stack-guard data are declared backing for two imported-data pointers. Pre-import builder execution depends on these bindings. | Verify both pointers/data and stop before the first import call. Actual native initialization and guard validity remain unknown. |
| HF7 | A declared 32-bit destination value establishes only serialization arguments. No right or endpoint conclusion follows. | Recover native request1200 reply/name history and matching delivery, rights, ownership and daemon/kext consumption separately. |

Universal SHA-256: `68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f`; selected arm64e SHA-256: `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. The complete parent `[0x8e81c8,0x8fcfa0)` is 85464 B, SHA-256 `4e0ebb4383ce0f3d074358e851dd1bdfff67e77d675e0cfa9e73b4a03ff9a94e`. Selected builder `[0x8d40,0x8ed4)` is 404 B; two call banks add 512 B. All are compared directly with the original file.

The predecessor checks SHA-256 is `e69211620dde7b07114a314849f0f786852d8fb75c146e45bd8fa557293a906b`; its independent audit SHA-256 is `d55c04ca84d34b0d6ae04f1d4e45a8eb72e4fdb43e0ab64e68d9a5465a9ab8da`. Its 16 retained arithmetic returns and two diagnostic shortened exports supply the first 18 checkpoints. No prefix instruction is rerun.

## Exact re-entry boundary and declared bindings [HF1-HF6]

The prior helper fixture returns to a private stop rather than its original parent. Its terminal state includes W20=`0x55e1`, W22=`0x7bd0`, W23=`0x3de80`, FP=`0x7100c000` and SP=`0x71008000`. W23 is source-defined at constructor `0x8f3450` as W22 shifted left by 3; it is not an additional new control. The root marker is at FP-0x88, and the wrapper's separate adjustment at SP+0x978 contains zero. The original parent starts by loading its context pointer, resets several scratch registers, consumes that adjustment and compares the root marker.

However, the earlier fixture's X19/X25 and several parent stack cells contain diagnostic values, not coherent native parent state. This increment therefore restores each exact old terminal state, retains all original output bytes, applies the following declared bindings, then sets PC to `0x8f3564`. It does not replay the original parent prologue or patch the helper's saved return address.

| Bound item | Declared value / purpose | Source role and limitation |
| --- | --- | --- |
| X19 | Original branch-table base `0x1c81940` | Complete-parent census finds only initializer `0x8e83ec` and epilogue restore `0x8fc42c` writing X19/W19; actual initializer path and callees still require continuity. |
| X25 and SP+0x1a8 | P+0x900, selected XOR destination | Original `0x8f3430` loads X25 from that cell before the constructor. This prefix is not rerun. |
| SP+0x1f0 | C=P+0x2000, retained context backing | Parent `0x8f3564` reloads X13 from this cell. Native context producer/epoch remains unknown. |
| SP+0x258 and P+0x168 | P and explicit scalar | Original `0x8f3634/0x8f3638` supplies the scalar gate and builder argument. No semantic name is assigned to this field. |
| SP+0x3a8 / SP+0x3a0 | Original call-bank roots `0x18ac270` / `0x1ac1ac0` | Every one of 256 possible selector bytes yields the same request1201 row. |
| SP+0x4c0 / SP+0x4b8 | Two declared global-word pointers | Original bank mixing executes. Retained X26 is preserved; native global state is not inferred. |
| SP+0x4e8 | Diagnostic destination `0x6800 + checkpoint index` | Parent loads W0 here. This value is not treated as a native Mach right. |
| Imported-data cells `0x1d1c570/0x1d1c578` | Declared NDR / guard backing | Necessary pre-import reads only; no imported function executes. |

P is private `0x73000000`. The already retained SP+0x1b8 pointer to P+0x880, candidate bytes, root marker and zero adjustment are preserved in ordinary profiles. Four explicit negative controls replace only the root marker in addition to the listed bindings. New memory regions and pointer normalization are declared emulator scaffolding. Complete before/after RAM is retained. These controls are not evidence that all bindings coexist in a native invocation.

## Root marker selects the actual parent branch [HF1-HF5]

The parent compares the root marker at FP-0x88 with `0xba1df9db`. With retained W22/W23, the table index is:

```text
equal = u32(root_marker == 0xba1df9db)
index = (equal * (0x3de80 XOR 0x31db5)) XOR 0x7bd0
      = 0xb8e5 if equal else 0x7bd0
```

A universal u32 solver obligation proves this partition; an independent reconstruction repeats it. The marker is the root record's +0x30 cell because FP-0xb8+0x30=FP-0x88. It is distinct from the exporter record's +0x18 status. The parent does not newly inspect that exporter status on these paths.

| Parent branch `0x8f35c8` | Index | Original slot / word | IA diversity | Target |
| --- | --- | --- | --- | --- |
| Root equals `0xba1df9db` | `0xb8e5` | `0x1cde068` / `0x80084cd4008f35cc` | `0x4cd4` | `0x8f35cc`, XOR loop |
| Every other u32 marker | `0x7bd0` | `0x1cbf7c0` / `0x80084cd4008f3664` | `0x4cd4` | `0x8f3664`, alternate continuation; stop here |

All 23 unaltered-root profiles take the first edge. Four marker controls, 0, `0x45e2a205`, `0xba1df9da` and `0xffffffff`, take the second. The alternate continuation is not classified as a complete failure/cleanup path; it is an unexecuted frontier in this increment.

## Distinct buffers and unsigned scalar gate [HF1-HF5]

The original loop reads C[127..0] at `0x8f35d0` and writes C[i] XOR `0xba` into P+0x900+i at `0x8f35e0`. Its 128 stores preserve P+0x880..P+0x8ff. After the loop, the parent loads W1 from the declared owner+0x168 field and compares it unsigned with 2. Original pointer rows give:

| Scalar condition | Index / slot | IA diversity | Original target / subsequent path |
| --- | --- | --- | --- |
| u32 scalar < 2 | `0xe297` / `0x1cf2df8` | `0x1347` | `0x8f365c -> 0x8f389c`, skip stop |
| u32 scalar >= 2 | `0xe28b` / `0x1cf2d98` | `0x1347` | `0x8f37d8`, load destination/source and call builder |

The complete u32-domain predicate is proved twice. The finite boundary controls include 0, 1, 2, 3, `0x80000000` and `0xffffffff`; the last two take the builder route. They are not negative signed selectors. On this route `0x8f3810` loads the declared destination into W0 and `0x8f382c` loads the unchanged candidate pointer into X2. `0x8f3838` calls `0x8d40` through original slot `0x1d03f08`, IA diversity `0x8390`, address diversity 0. All 256 bank selector cases select that row.

```text
retained helper terminal RAM
  P+0x880: 128-byte padded big-endian export --------------+
  root+0x30: root marker                                  |
  SP+0x978: zero adjustment                               |
         | declared parent bindings                      |
         v                                               |
  parent marker compare -> success -> C XOR 0xba          |
                                     -> P+0x900          |
         | unsigned scalar >= 2                          |
         v                                               |
  reload candidate P+0x880 <------------------------------+
         -> builder payload copy -> stop before first API
```

The three owner ranges remain distinct: P+0x800 is the earlier conditional request1200 output, P+0x880 is the candidate/exported request1201 source, and P+0x900 is the XOR-loop destination. This local continuation joins the last two roles under HF4; it does not join the earlier request1200/native owner epochs.

## Pre-import serializer state and port boundary [HF1-HF7]

Builder `0x8d40` reserves 208 B. Let S be its entry SP and M=S-208+4 be its future message pointer. The request header has not been fully constructed at this increment's stop. The following fields have already been written by original instructions:

| Relative field | Extent | Source / original stores |
| --- | --- | --- |
| M+24 | 8 B NDR data | Declared imported data, `0x8da4` |
| M+32 | 4 B scalar | W1, `0x8da8` |
| M+36 | 128 B inline payload | P+0x880, SIMD copies `0x8d6c..0x8dac` |

Eight architectural 16-byte payload loads and eight 16-byte stores copy the input in four 32-byte groups. The emulator journals each 16-byte access as two 8-byte events; the independent auditor checks all 16 read and 16 store events per payload, exact addresses and bytes. The source is not XOR-transformed by the builder. Every new original store before the stop is disjoint from the candidate input range; the source pointer and destination-value stack cells remain unchanged throughout the selected local continuation.

At `0x8db0`, the next instruction would call `_mig_get_reply_port` through stub `0x15d1934`. The emulator stops before executing that BL. Thus no reply-port result is needed and no import-stub/function or target-host operation executes. The already recovered complete builder would later construct the header and call `_mach_msg` at `0x8e04`, sending 164 B with 44 B receive capacity. That later API and its effects are not executed here. Header completion, voucher behavior, port acquisition/lifetime, actual sending and reply parsing retain the [client report](fpsd1201_client_report.md)'s separate evidence boundaries.

The 16 unchanged retained outputs and two shortened-export controls all stage 128 B with scalar 2. In the shortened controls, the prior exporter rejected length 0 or 3, left the candidate's diagnostic `0xa5` bytes unchanged, and the root helper still published its own success marker. This declared re-entry follows that marker and copies those unchanged bytes into the payload staging area. This extends the local status-flow observation through serialization preparation; it does not establish native admission, a sent malformed request, external controllability or a vulnerability.

Original saved nominal modulus width 8 B, later diagnostic working modulus width 4 B and staged payload length 128 B remain separate. No new numerical result or modulus/exponent is supplied. Matching staged bytes do not establish native ownership, protected-transaction completion or that the receiving endpoint is the FairPlayIOKit kext.

## Independent validation and bounded continuation

Fresh independent replay passes all 27 profiles: 21 pre-import builder stops, two scalar skip stops and four root-mismatch stops. It checks 37699 original visits, 6741 reads, 3473 writes, 3036 PAC models, 3259 complete CPU frames, 142 selected CPU points, 382 explicit memory bindings, 2944 XOR byte oracles and 2688 serialized payload bytes. Restored, initial and final RAM each total 4423680 B. All 27 profiles preserve the candidate. Source validation checks 86380 B, 79512 original fixup words, 25 exact instructions, the complete-parent X19 writer census, 256 request-bank cases and two retained plus two independently reconstructed UNSAT obligations. The prefix is receipt-pinned, not rerun; the complete native parent is not replayed.

| Impact | Bounded continuation | Falsification / remaining boundary |
| --- | --- | --- |
| High | Recover actual parent cells, owner/context identity and frame epochs before `0x8f3560`. | Replace each HF4 binding with a source-produced value and coherent predecessor journal; repeated nominal SP offsets alone are insufficient. |
| High | Establish request1200 returned name -> request1201 destination -> daemon receive/right history. | Match native endpoint identity, right dispositions and lifetime across real messages. The declared W0 value proves none of these. |
| High | Recover native arithmetic capacity and input admission. | Show actual modulus/exponent producers and length invariants before generalizing either short-export control beyond private input. |
| Medium | Continue the original alternate root-marker path and post-request cleanup. | Current mismatch stop precedes `0x8f3664`; no complete error/cleanup classification follows from its address. |
| Medium | Complete real initialization of NDR/guard/global state and authenticated rows. | Current pointer/data/PAC models admit local execution but do not prove native initialized state or concurrent visibility. |
| Low | Extend parent continuation to wider original arithmetic fixtures. | Payload serialization preserves any backed 128-byte input; tested helper arithmetic widths remain those of the earlier reports. |

Quality gates: **QG1** factual technical analysis requires no normative content. **QG2** HF1-HF7 state dependencies and falsification probes. **QG3** this increment covers the post-helper status/control flow, source/destination buffers, scalar ABI, exact local stores, builder copy and port/API boundary. **QG4** B denotes bytes; u32 arithmetic, unsigned scalar comparison, stack/message offsets and producer/auditor complexity are explicit. **QG5** root/export statuses, three buffers, saved width/output length, source/API access widths, declared/native state and alternate/skip/build routes remain distinct. **QG6** original file bytes, retained IDA source, exact pointer words, pinned predecessor receipt, independent replay and byte oracles support claims. **QG7** impact-ranked continuation is bounded. The full investigation remains active.
