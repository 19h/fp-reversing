# Launchd variant binding for host-special publication

The original `/sbin/launchd` contains two arm64 slices. The earlier host-special report recovered the normal `arm64e` slice. This increment independently recovers the corresponding eleven roles from `arm64e.x1` and verifies selected property, publication, cleanup and XPC/Mach interface contracts in both slices. Native PID 1 slice selection remains **unknown**: the read-only `PROC_PIDARCHINFO` query returned zero bytes and `EPERM`. A successful path query identifies `/sbin/launchd`; it does not identify a universal-binary slice. [Earlier registration report](host_special_registration_report.md), [original-byte capture](triage_evidence/launchd_variant_binding_source.json), [frozen metadata queries](triage_evidence/launchd_variant_binding_observations.json).

## Provenance and identity

The universal file is 1,319,360 B, SHA-256 `1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168`. Slice extents, UUIDs, imports, compiler starts and chained fixups are read independently for each slice. Addresses below are unslid virtual addresses from that slice; no constant address delta is assumed. CPU type is `0x0100000c` in both headers. [Capture and dependency hashes](triage_evidence/launchd_variant_binding_source.json).

| Property | arm64e | arm64e.x1 |
|---|---|---|
| Raw CPU subtype, including capability bits | `0x80000002` | `0x8000000c` |
| SDK subtype after capability masking | `CPU_SUBTYPE_ARM64E = 2` | `CPU_SUBTYPE_ARM64E_X1 = 12` |
| File offset, B | 16,384 | 671,744 |
| Slice length, B | 647,632 | 647,616 |
| UUID | `f5ce73f2-36d5-3916-8ab0-ee0d6c8a1d71` | `62af2b7d-327e-334a-a1d7-83777efc3c12` |
| Slice SHA-256 | `c8593a95e0937884b71e014c38b27f84db2c292f6a5e904a452d69a9a365bdb6` | `c7ca2883eefa4264d7f42fa8a8e2585a5406494dab564af39558e4cb5be2fc64` |
| `__text` extent, B | 377,680 | 373,524 |
| Selected body instructions | 1,194 | 1,176 |
| Selected words requiring LLVM decoding | 0 | 27 |
| Chained fixups compared with `dyld_info` | 2,447 | 2,447 |

`__text` differs in extent by 4,156 B; this is a file-section comparison, not an estimate of execution cost. `__cstring` is 94,135 B and byte-identical across slices. The file-backed `__auth_got` and `__got` bytes also match. No `__bss`, `__common`, or other zero-fill section is treated as file content. Identical raw GOT words do not imply identical resolved runtime pointer values or authentication contexts. [Section hashes](triage_evidence/launchd_variant_binding_source.json).

## Recovered role correspondence

Role names are analytical labels. Correspondence uses import-bound setter callers, literal references, parser callback references, call edges and instruction signatures. The constructor's retained caller context is not conclusively typed as a job. All eleven normal-slice body byte spans match the earlier capture exactly. [Instruction checks](triage_evidence/launchd_variant_binding_checks.json).

| Analytical role | arm64e start | arm64e.x1 start | Instructions, normal / x1 |
|---|---|---|---|
| Fixed slot 22 startup publication | `0x10002d3a8` | `0x10002ca6c` | 73 / 73 |
| Service cleanup | `0x10002fd84` | `0x10002f3b8` | 161 / 155 |
| Service publisher | `0x10003012c` | `0x10002f730` | 287 / 287 |
| Fixed slot 16 publication | `0x100035930` | `0x100034ef8` | 65 / 65 |
| Property parser callback | `0x10005c840` | `0x10005b810` | 203 / 203 |
| Service constructor / parser-block producer | `0x100047064` | `0x100046328` | 121 / 121 |
| Task-special field validator/writer | `0x1000479cc` | `0x100046c54` | 24 / 24 |
| Owner/domain query | `0x100003708` | `0x1000036d8` | 119 / 116 |
| Send-name extraction helper | `0x100046c28` | `0x100045ef8` | 18 / 15 |
| XPC Mach send-object helper | `0x10005cb6c` | `0x10005bb3c` | 82 / 82 |
| Exception-port setter helper | `0x100043fd0` | `0x10004336c` | 41 / 35 |

```text
HostSpecialPort integer property
       |
       v
parser -> u32 service+0x54 -> publisher admission / slot24 split
                                      |
                              send-object -> send-name
                                      |
                         _host_set_special_port(host,index,name)
                                      |
                           result test / diagnostic
                                      |
                          local publisher cache store
```

This is a static relationship between roles. Constructor-to-publisher object identity for a particular running service, actual kernel registration, and the deeper XPC endpoint factory are unknown [VB2, VB4]. The user-library RPC413 and kernel replacement path are established separately in the [registration report](host_special_registration_report.md); no new native setter invocation occurred.

## Incoming configuration, outgoing ports and emission sites

These four direct B/BL candidates exhaust the aligned `__text` scan to the import-bound `_host_set_special_port` stub in each slice. The scan excludes indirect calls, other executable sections/images and runtime-generated code. Each candidate's containing compiler-bounded body is captured in full. [Raw branch words and stub bindings](triage_evidence/launchd_variant_binding_source.json).

| Role / argument evidence | arm64e call site | arm64e.x1 call site |
|---|---|---|
| Fixed index 22 (`W1 = 0x16`) | `0x10002d498` | `0x10002cb5c` |
| Cleanup, index in X20, `W2 = 0` | `0x10002fec8` | `0x10002f4f0` |
| Ordinary service publication, index X21, extracted name W2 | `0x10003055c` | `0x10002fb60` |
| Fixed index 16 (`W1 = 0x10`) | `0x100035a04` | `0x100034fcc` |
| Bound setter stub | `0x10005e260` | `0x10005d224` |

Both selected publishers load signed service+`0x54` into X21. A zero low word bypasses publication; index 24 enters the separate exception-port helper. The ordinary path obtains the host name via `_mach_host_self`, invokes the send-name helper with `W1 = 1`, carries its result in X2, and calls the setter with index X21. The send-name helper calls the send-object helper, then tail-calls `_xpc_mach_send_get_right`; the send-object helper passes disposition 17 to `_xpc_mach_send_create_with_disposition`. These instructions establish argument production and import binding. Actual task-local names, runtime port objects, right counts and destination receivers are unknown [VB2, VB5]. [Checks](triage_evidence/launchd_variant_binding_checks.json).

The configuration and lifecycle distinctions recovered previously also appear in both slices:

| Contract | Evidence in both selected bodies | Interpretation boundary |
|---|---|---|
| Integer `HostSpecialPort` | Signed 64-bit lower comparison against 8, unsigned upper comparison against 36, 32-bit store to service+`0x54` | This is one writer; an earlier publisher flag path can write 24 |
| Task-special numeric helper | Unsigned `W1 > 6` reaches signed `W1 <= 11` store to service+`0x50` | Accepts 7..11 and low-32-bit signed-negative values; full 64-bit positivity is not established |
| Owner queries 2 and 3 | Ten signed relative jump-table entries; entries 2/3 share their destination in each slice | Shared code destination, not a runtime owner identity observation |
| Owner predicate | Retained bit-6 extraction from owner+`0x586` and result masking | Wider predicate/admission context remains in full captured body and prior report |
| Flag-driven writer | Writes task+`0x50` or host+`0x54`, including host value 24 | Integer parser range does not enumerate all field producers |
| Selective cleanup | `(u32(index) & 0xfffffffb) == 25`, then null-name setter | Only indices 25 and 29 satisfy this equality; local cache clearing has a broader path |
| Ordinary setter failure | Nonzero W0 reaches `__os_assumes_log`, then branches back to the same cache-store site | A local cache entry or ordinary function result zero does not prove kernel registration |

The cache-store sites are `0x100030564` and `0x10002fb68`; the error-log calls are `0x100030594` and `0x10002fb98`. This increment checks branch convergence and exact argument/register instructions. It does not claim equivalence of every basic block, exception behavior, pointer arithmetic, or pointer-authentication semantics [VB3]. [102 selected instruction assertions](triage_evidence/launchd_variant_binding_checks.json).

## Decoder boundary and environmental evidence

The per-word capture compares all 2,370 selected instruction words (9,480 B) with the original bytes and LLVM's printed bytes. Capstone supplies 2,343 records; LLVM supplies the remaining 27 records, all in the x1 slice. The LLVM names in those 27 records are `pacibsppc`, `autibsppc`, `retabsppc`, and `addpt`. For example, x1 publisher `0x10002f9dc` is bytes `48 2d 09 9a`, decoded by LLVM as `addpt x8, x10, x9, lsl #3`. Architectural semantics, authentication success and execution on hardware were not tested. Treating an unsupported word as a NOP, or silently stopping at it, would lose instruction coverage. [Per-word records and tool hashes](triage_evidence/launchd_variant_binding_source.json).

The full-image LLVM runs each returned zero and each emitted 16 invalid-encoding warnings elsewhere. Selected spans have one byte-matching, non-unknown LLVM row per 4 B word. Full-image decoding is not established. Compiler-start bounds are retained as bounds of the analyzed spans, not proof of every possible entry point [VB3].

The frozen read-only metadata snapshot records three calls: PID 1 architecture query, inspection-process architecture control, and PID 1 path query. PID 1 architecture: return 0, `errno = 1 (EPERM)`, initialized buffer unchanged; its zero bytes are **not** a CPU subtype. Control: return 8 B, CPU type `0x0100000c`, subtype 0. PID 1 path: return 13, `/sbin/launchd`, errno zero. The control describes the Python inspection process, not launchd. Validation reads the frozen snapshot and never repeats the metadata calls. No task port, privilege change, service mutation, target launch/injection, host-special setter call, or FairPlay request was used for this increment. [Snapshot](triage_evidence/launchd_variant_binding_observations.json).

## Assumption register and falsification probes

| ID | Assumption / dependent result | Stress test or falsification probe | Status |
|---|---|---|---|
| VB1 | Original file identity anchors both slice results | Rehash full file, each exact slice and tool; independently parse slice imports/fixups | Passed for captured files; future file replacement requires recapture |
| VB2 | Static role correspondence informs the launchd side of the FairPlay publication boundary | Match literal, callback, import and selected argument/control edges in each slice; a runtime object trace could falsify a service-specific application | Static correspondence passed; running service-object identity unknown |
| VB3 | Compiler spans and LLVM records cover the selected instruction words | Require contiguous 4 B rows and exact raw bytes; compare Capstone records where supported; retain global warnings | Selected coverage passed; full semantic/ISA equivalence unknown |
| VB4 | A PID 1 path identifies a file but not the selected slice | Require exactly 8 returned architecture bytes before decoding; contrast with independent control | PID 1 denied; native selected slice unknown |
| VB5 | Register carriers and numeric dispositions identify interface arguments | Resolve import stubs independently, compare 4,894 fixups and inspect full helpers; runtime names/object/refcount observation could refine or falsify endpoint identity | Argument production verified; native rights and peer identity unknown |
| VB6 | Prior normal-slice report remains applicable to its original bytes | Compare every one of the eleven normal body byte spans with prior source capture | All eleven match; broader prior conclusions are not re-proved here |

## Bounded continuation opportunities

| Impact | Remaining question | Concrete discriminating evidence |
|---|---|---|
| High | Which live service object and kernel slot back the managed RPC700 path? | Existing read-only service/port metadata correlated with slot/receiver identity; property declarations and cache stores alone cannot establish this |
| High | Where does the send-object helper obtain its underlying endpoint? | Statically follow its port factory and ownership edges, retaining callback and refcount boundaries; correlate the returned object with the publication caller |
| Medium | How do x1-only pointer instructions affect unexamined object/table accesses? | Original-byte architectural instruction documentation and explicitly scoped semantics; the present capture provides names/words, not a hardware model |
| Low | Can role correspondence cover other launchd interface paths? | Repeat import/literal/call-edge discovery per role; avoid numerical address translation and unbounded whole-function equivalence claims |

## Reproduction, coverage and quality gates

From the extracted directory, use `/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_launchd_variant_binding.py`. This recaptures static source/tool outputs, verifies selected contracts, compiles 16 assertions against the installed SDK, and rejects eight altered evidence records. It does not refresh process observations. Do not use `--observe` to validate the historical snapshot; the recovery script refuses to overwrite it. [Recovery](triage_evidence/recover_launchd_variant_binding.py), [validator](triage_evidence/validate_launchd_variant_binding.py).

Capture/validation scan 187,801 aligned text words, compare 4,894 fixups and check 22 full compiler-bounded bodies. Time and space are O(B+F+I) for file bytes B, fixup records F and selected instructions I; bounded role discovery repeats a fixed number of text scans. SDK checks cover 32-bit CPU types/subtypes, 8 B `proc_archinfo`, 4 B subtype-field offset, subtype capability masking and flavor 19. They are compilation checks, not a kernel query-success guarantee. Eight altered evidence records are corruption/sensitivity checks, not a vulnerability test, parser-fuzzing campaign or proof of decoder correctness. [Counts and check records](triage_evidence/launchd_variant_binding_checks.json).

QG1: Factual interface analysis; no normative judgment required.

QG2: VB1-VB6 identify assumptions, dependent conclusions and falsification probes.

QG3: This increment covers slice identity, role correspondence, selected publication/cleanup contracts and a frozen metadata boundary. The broader interface goal remains active; native registration, slot34/RPC700 receiver and successful daemon/kext exchange remain unknown.

QG4: Extents are B, instruction words are 4 B, CPU fields are 32 bit and field/disposition widths are explicit. No timing or hardware-performance claim is derived from text size.

QG5: Slice-specific addresses, global decoder warnings, selected decode coverage, metadata denial and local-cache/kernel-registration distinction remain separate.

QG6: Claims are pinned to original file/slice/tool/SDK/dependency hashes, exact instruction bytes and frozen observation results. SDK nomenclature comes from the captured installed primary headers; no exact native slice or hardware authentication result is inferred.

QG7: The bounded continuation table labels impact and discriminating evidence.

Publication evidence: [prior manifest](triage_evidence/launchd_variant_binding_prior_manifest.json), [preservation seal](triage_evidence/launchd_variant_binding_delivery.json), [scoped gates](triage_evidence/launchd_variant_binding_quality_gates.json), [seal script](triage_evidence/seal_launchd_variant_binding.py), [independent audit](triage_evidence/verify_launchd_variant_binding_publication.py), [current corpus manifest](triage_evidence/interface_manifest.json). Gates apply to this increment; `full_goal_complete = false`.
