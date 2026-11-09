# A70 terminal output clearing, result publication and stack epochs

At the recovered terminal gate, phase W19=0x6cf4 partitions the raw u32 result exactly: marker 0x8b3dc651 bypasses output clearing; every other value clears two borrowed 8 B cells, then publishes the result. The XPC caller produces these addresses as pre-call SP+0x408 and SP+0x6e8. This resolves the former clearing-store destination contract under a valid preserved caller frame. It does not establish native execution of an allocation-failure path. [EO1-EO5]

The caller subsequently adjusts SP by a budget-derived delta. Equality between the cleared cells and later SP-relative output loads requires delta=0. That equality is not implied by matching SP immediates. The complete budget write history remains unknown. The result read uses FP and is independent of this SP adjustment. [EO3,EO6]

Primary source: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Addresses are unslid VAs; offsets/constants are hexadecimal; byte counts are decimal. Evidence: [original capture](triage_evidence/daemon_xpc_error_outputs_source.json), [independent checks and complete SMT queries](triage_evidence/daemon_xpc_error_outputs_checks.json), [preservation](triage_evidence/daemon_xpc_error_outputs_delivery.json), [scoped quality gates](triage_evidence/daemon_xpc_error_outputs_quality_gates.json). Original binaries, trace, previous reports/evidence and IDBs are preserved.

## Cell ownership and exact source sites

Let C be the XPC frame SP at construction, K the shared-core local frame SP, B=C+0x850 the 72 B argument record, and P=caller FP-0xa0 the 32 B protected record. The XPC prologue establishes FP=C+0xf30 for its unadjusted local frame; the corresponding P is C+0xe90. These equations refer to one frame epoch. [EO2,EO3,EO6]

| Producer/consumer | Exact effect | Width |
| --- | --- | --- |
| 0x100a86d08 / 0x100a86d10 | B+56 := C+0x408 | Address stored as 8 B |
| 0x100a86d0c / 0x100a86d14 | B+64 := C+0x6e8 | Address stored as 8 B |
| 0x100592ef0 | Load B+56/B+64 into X24/X27 | Two 8 B values |
| 0x100592ef4 / 0x100592f3c | Save addresses in K+0x1a30 / K+0x7098 | Two 8 B values |
| 0x1004c24bc | Save protected-record pointer X0 in K+0x580 | 8 B |
| 0x1007fb774 | Reload raw result from K+0x44a4 into W6 | 4 B, zero extension |
| 0x10057a770 / 0x10057a774 | Reload first borrowed address; store zero through it | 8 B clear |
| 0x10057a778 / 0x10057a77c | Reload second borrowed address; store zero through it | 8 B clear |
| 0x100528dd8 / 0x100528ddc | Reload P; P+24 := W6 | 4 B result store |
| 0x100a86e50 | Read P+24 through caller FP-0x88 into W20 | 4 B, zero extension |

The stores clear the caller's pointer and extent cells. They do not erase a pointed-to buffer or free an allocation. The terminal clear block contains no API call. The earlier 32 B internal-object free and VM cleanup have separate owners and PCs in the [VM cleanup report](daemon_vm_cleanup_report.md). [EO2-EO5]

The [shared-core bridge](daemon_xpc_core_bridge_report.md) supplies the selected call/argument correspondence; [handover](daemon_mig_handover_report.md) supplies the A70 operation and copied audit token. The new raw source recapture includes the XPC producers, A70 saves, protected-pointer save prefix and both terminal consumers. It does not claim every intervening predecessor or alias write is recovered.

## Terminal control flow and return ordering

```text
W19=0x6cf4; s = u32[K+0x44a4]
  w8 = ((0x6cf4 - 0x5bf2) | 0x8a1) = 0x19a3
  |
  +-- s == 0x8b3dc651 --> table[0x4314] ---------+
  |                                            |
  +-- s != 0x8b3dc651 --> table[0x4302]         |
       -> 0x10057a770                          |
       -> clear [C+0x408], then [C+0x6e8]       |
       -> table[0x19a3] -----------------------+
                                                v
                                       0x100528dd8
                                       write u32 P+24 = s
                                       compare saved/live canary
                                         equal -> restore frame -> RETAB
                                         unequal -> ___stack_chk_fail
```

| Logical edge | Original slot | Target | IA diversity |
| --- | --- | --- | --- |
| Marker from 0x1007fb7ac | 0x10105b790 | 0x100528dd8 | 0x2803 |
| Nonmarker from 0x1007fb7ac | 0x10105b700 | 0x10057a770 | 0x2803 |
| After clearing, 0x10057a78c | 0x101046c08 | 0x100528dd8 | 0x8bfa |

All three original format-12 words use IA with address diversity zero. They are verified against the fresh `dyld_info` fixup walk; hardware authentication is not executed. The all-u32 partition proof assumes W19=0x6cf4 and the original table base at K+0x9d8. It does not quantify arbitrary dispatcher phases. [EO1,EO2]

Both output clears and the result store precede the canary comparison at 0x100528df0. An unequal canary branches at 0x100528df4 to the BL at 0x100528e24, then stub 0x100e2aad0 / import slot 0x1010b1d00, bound to `___stack_chk_fail`. Mutation of the cells/result therefore does not imply completion of the caller's reply path. With invalid cells, a fault could occur before the subsequent stores; the component contract assumes valid writable cells throughout. [EO3,EO4]

Let E be core entry SP. The prologue saves 128 B and allocates 68,944 B (0x10d50), so K=E-69,072 B (0x10dd0), core FP=E-16 B, and the saved guard is at E-152 B. The equal branch adds 0x10d50, restores X19-X30 and D8-D11 from the matching saved slots, then consumes the remaining 128 B and uses RETAB at 0x100528e20. Only the lower 64 bits represented by each D register are included in this source projection. The inverse stack equation is proved for arbitrary u64 E; accessible/nonwrapping frame storage, preserved saved state and successful hardware PAC remain separate premises. [EO3,EO4]

## Retained allocation failures and conditional XPC status

The new capture inspects 80 historical private cases and recaptures 291,680 original instruction visits from the 64 cases stopped immediately before 0x10057a774. There are 2,689 unique visited instructions. Sixteen cases carry the first-allocation-null result; 48 carry the second-allocation-null/cleanup result. None writes K+0x580, K+0x1a30 or K+0x7098 during its retained interval. These are historical model states, not 64 native failures, relocated XPC cases or new target executions. Their earlier policy, allocator, API-return and image-state premises remain in force. [EO5]

| Historical case class | Raw W6 | XOR 0x8b3dc651 | Signed result, if consumed by recovered XPC decoder |
| --- | --- | --- | --- |
| First malloc(32) returns NULL | 0x74c29d85 | 0xffff5bd4 | -42028 |
| Second malloc(16) returns NULL; retained cleanup returns | 0x74c29d69 | 0xffff5b38 | -42184 |
| Terminal success marker, component comparison | 0x8b3dc651 | 0x00000000 | 0 |

For example, `0xffff5bd4 = 4,294,925,268`; signed conversion subtracts `2^32 = 4,294,967,296`, giving -42,028. The distinct second value is 4,294,925,112 - 4,294,967,296 = -42,184. Semantic error names are unknown. The direct A70 invalid-pointer result 0x74c29d88 is a separate path and is not added to these historical clearing cases. [EO5,EO7]

Under normal core/adapter returns and preserved caller state, the [reply contract](daemon_xpc_reply_lifecycle_report.md) reads raw P+24 and applies signed32-to-int64 conversion after XOR. A nonmarker takes the branch bypassing `_xpc_dictionary_set_data`; with event, saved peer and created reply present, `_xpc_dictionary_set_int64` occurs at 0x100bb4cb8, send at 0x100bb4d08 and reply release at 0x100bb4d50. This identifies a conditional status-only reply route. It establishes neither actual native admission nor message delivery. [EO4-EO7]

## Budget protocol and the remaining frame join

The returning adapter writes delta to the caller's local word, restores its own frame, and returns. The caller loads this word at 0x100a86e44 and applies it to SP at 0x100a86e4c. For incoming adapter seed V and returned budget word Q:

```text
adapter initial u64 budget = V - 0xe0                  0x100660178..17c
core entry update        = budget + 0xe0             0x10061a458..460
delta = zero_extend64(low16(u32(Q)-low32(V))) * 16 B  0x100660230..23c
S_after = C + delta                                  0x100a86e40..4c
```

The first two operations cancel modulo 2^64 if there are no further relevant budget writes. That condition is not proved for the entire core path. Delta lies in {0,16,...,1,048,560} B and equals zero iff low16(Q)=low16(V). No value of V or Q is assigned as a native observation. [EO6]

| Consumer after return | Address relation | Required join |
| --- | --- | --- |
| Raw status load | FP-0x88 = P+24 | Preserved FP and protected record; independent of delta |
| Output pointer load | C+delta+0x408 | Same pre-call cell iff delta=0 |
| Output extent load | C+delta+0x6e8 | Same pre-call cell iff delta=0 |
| Output free gate | Reads SP+0x408 | Cleared pointer implies skipped free only with delta=0 and no intervening writer |

The byte-array proof uses the unadjusted caller-frame projection: two 8 B zero stores plus the 4 B result at C+0xea8, preserving every other byte. It is a component theorem about exact widths and offsets, including arbitrary initial bytes and arbitrary raw status. It does not supply lifetime, mapping, control continuity or delta stability. [EO3,EO6]

This qualifies the earlier destination-gap interpretation: there is now a concrete producer for the clearing addresses, while the subsequent SP-relative read epoch remains conditional. No earlier evidence file is rewritten to imply that missing join was proved.

## Validation and reproduction

Fourteen original ranges retain 239 instructions / 956 B. Thirty-five prior source ranges are freshly compared over 6,044 B. The six selected pointers and all 61,737 fixup catalog memberships are checked. The validator re-disassembles retained bytes, performs instruction assertions, compiles eleven LP64/record/API assertions without execution, solves five complete SMT queries, checks 36 finite component combinations and rejects eight altered-evidence controls. The checks JSON gives exact assertion counts, pinned tools, queries, cases and dependency hashes.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_xpc_error_outputs.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_xpc_error_outputs.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/seal_daemon_xpc_error_outputs.py
```

Capture/check complexity is O(image bytes + fixups + retained visits + captured source bytes), with space O(image + largest retained JSON + unique visited instructions). The terminal transfer itself has O(1) time/space; SMT resources are additional. All source values use little-endian u32/u64 and modular arithmetic at the stated width. No new target API, signal, process control, IPC, recovered-code execution/emulation or IDB mutation is performed. Reference files suffice; no new IDA query is required.

## Assumption register

| ID | Premise | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| EO1 | Pinned original image and its fixups are authoritative | PCs, instructions, slots, imports | Rehash; recapture bytes; compare fresh fixup membership and selected records |
| EO2 | Terminal phase W19=0x6cf4, original table and matching core frame/record epoch hold | All-u32 marker partition and logical edges | Recover each incoming phase/table producer; reject other phases or frame substitutions |
| EO3 | Caller/core owners are valid, writable, nonwrapping, distinct where required, and relevant cells/saved state survive | Actual clearing/result effects, frame restore and byte theorem application | Establish complete predecessor/alias writes and concrete owner lifetimes; component proof alone is insufficient |
| EO4 | Required APIs/core/adapter return normally, guard equality and logical saved-link continuity hold | Post-core XPC status and possible reply route | Inspect actual normal return, guard and saved link; native PAC/exceptional API effects remain unknown |
| EO5 | Historical private cases retain their original framework/allocator/global-state premises | Two raw failure classes and watched-cell survey | Rehash journals and original visits; do not substitute XPC pointers or infer native occurrence |
| EO6 | Delta=0 and no intervening writer are additionally required for post-return output-cell equality | Cleared D/N consumed later, skipped output free | Recover complete budget/alias write history; compare Q/V low16 and actual before/after SP |
| EO7 | Recovered status decoder applies on the selected reply path; semantic names/native delivery are unknown | Conditional signed errors and status-only send | Follow P+24/W20 and reply guards; require actual transport observation for delivery/identity |

## Bounded continuation targets

| Impact | Evidence target | Uncertainty resolved |
| --- | --- | --- |
| High | Complete budget pointer escape/write history across core entry, A70 and returns | Whether delta zero follows from source continuity |
| High | Success-path writers of the two caller output cells and allocated output storage | Output format, length, owner and copy/free contract |
| High | Continuous source path from the XPC producer through policy and allocation results | Reachability of these terminal statuses under actual peer/context |
| High | Native successful daemon/kext selector26 and RPC502/700 pairing | Actual port/right identities and exchange; still unknown |
| Medium | Other direct users of the same terminal epilogue | Additional operation/result domains without conflating phases |
| Low | Matching semantic error definitions in build-compatible headers/resources | Names for decoded statuses; arithmetic alone supplies no names |

QG1: Pass; factual source/interface analysis.
QG2: Pass; EO1-EO7 specify assumptions, dependencies and falsification probes.
QG3: Pass for this increment; obfuscated terminal roles, cell data flow, control/return gates and existing emission touchpoints are reported. The full interface goal remains active and incomplete.
QG4: Pass; exact widths, B extents, modular/signed conversions, complete queries and complexity are explicit.
QG5: Pass within scope; pre-call cells versus post-delta cells, result mutation versus guarded return, historical models versus native execution and marker preservation versus successful output production are distinct.
QG6: Pass; original bytes/fixups, rechecked frozen journals, installed compile-only headers and full solver queries provide primary provenance.
QG7: Pass; continuation targets and their impact are bounded above.
