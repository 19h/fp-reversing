# Auxiliary extent gate and reverse byte transcode

The second-command auxiliary callback at `0xfffffe000a65fea8` admits copying only when its success flag is one and the auxiliary extent equals the low32 bits of the original argument. The admitted saved-mode branch loads separate auxiliary and staging pointers. Its byte step decrements the cursor, reads an auxiliary byte and writes the same decoded value under the staging buffer's address-dependent mask. The next cursor is zero on the cleanup edge. The original argument producers establish mode=N XOR 0x7c233caf and counter=N, where N=low32(argument64). Under the stated custody, memory and pointer premises, zero length bypasses copying and positive length yields exactly N reverse steps. The linked [emission report](userclient_serializer_emission_report.md) now establishes conditional emission-to-callback flow; complete native reachability remains unknown.

## Evidence and claim register

The [extractor](triage_evidence/recover_userclient_auxiliary_copy.py), [instruction audit](triage_evidence/audit_userclient_auxiliary_copy.py), [delivery verifier](triage_evidence/verify_userclient_auxiliary_copy_delivery.py), [checks](triage_evidence/userclient_auxiliary_copy_checks.json.zst) and [proofs](triage_evidence/userclient_auxiliary_copy_audit.json.zst) retain the selected source bytes, formulas and evidence boundaries. Primary sources are the original kernel collection and normalized kext. Predecessors cover [query requests and auxiliary aliases](userclient_query_records_report.md), [staging](userclient_container_staging_report.md), [final copy-back and retirement](userclient_caller_return_report.md), and [provider transfers](userclient_transfer_boundary_report.md).

| Claim | Established result | Dependencies |
| --- | --- | --- |
| AC1 | The selected publication block stores the auxiliary pointer and encoded extent, sets flag1/raw SUCCESS and returns to the saved callback | AC-A1-AC-A4 |
| AC2 | For incoming flag0/1, the callback selects the copy-mode gate exactly when flag1 and M=low32(argument64); all other cases select common cleanup | AC-A1-AC-A5 |
| AC3 | The next gate loads C+0x358, C+0x3c0 and F+0x5b8 as separate staging, auxiliary and counter channels; mode0x7c233caf bypasses copying | AC-A1-AC-A5 |
| AC4 | For any admitted positive counter T, one step uses j=T-1, reads A+j, writes Z+j and selects cleanup iff j=0 | AC-A1-AC-A6 |
| AC5 | The single-byte transformation preserves decoded content between the exact auxiliary and staging mask pairs | AC-A1-AC-A6 |
| AC6 | The byte step preserves the phase roots, buffer bases, key registers and cursor-adjustment constant required by another step | AC-A1-AC-A6 |
| AC7 | Eight spans, 128 captured words, 126 modeled locations, 12 nonvacuous source obligations, one predecessor recheck and a literal-mutation SAT control support these conditional contracts | AC-A1-AC-A7 |

Normalized image SHA-256: `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Original collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. All 128 selected words and five separately captured terminal transfers match both images. Eight original chained pointers are checked against normalized table targets. Two straight-line register-retention ranges contribute 763 structural instruction instances. Two captured MOVK retag alternatives are excluded under explicit nominal-pointer branch guards; they are not counted among 126 modeled locations.

Decoded checks SHA-256: `cdef998bcf4122a5ef2c858eda22c5082379ae08b0d83ad52da2ca0d560286ed`. Decoded audit SHA-256: `d8744eff77ad683456ebf8030a1a63e6f0b98bac8da2be6d7ccde24b037bb90b`. The audit records 698 proof instruction instances. No target execution, native memory effect, live IDA observation or IDB change supplies this increment.

## Publication and exact callback gate

F is the selected frame SP, C the outer context, S the workspace, A the auxiliary allocation, Z the protected staging allocation and M the auxiliary extent in bytes. `SUCCESS=0x31ae0066`, `TOKEN=0x886a1ca3`. All indicated control/extent words are u32; pointers and saved argument/counter channels are u64.

| Source location | Effect or interface |
| --- | --- |
| `0xfffffe000a65fe74` | Stores X10 through the pointer cell loaded from C+0x548 |
| `0xfffffe000a65fe78` | Stores W28 through X21; selected cut supplies X21=S+0xbe4 and W28=M XOR SUCCESS |
| `0xfffffe000a65fe7c` | Loads saved callback from C+0x468 |
| `0xfffffe000a65fe84` | Sets W8=1, followed by W23=SUCCESS |
| `0xfffffe000a65fe94` | Selected index0x217 reaches `0xfffffe000a65fe98`; its return restores X28=X27 and branches to the saved callback |
| `0xfffffe000a65fec4` | Loads &S+0xbe4 from F+0x888, then its encoded extent32 |
| `0xfffffe000a65fecc` | Loads original argument64 from F+0x878; the following XOR consumes only W12 |
| `0xfffffe000a65fee4` | Compares `(M XOR SUCCESS) XOR low32(argument64)` with SUCCESS |
| `0xfffffe000a65fee8` | Clears the incoming flag on extent mismatch |

The comparison reduces exactly to M=low32(argument64). Thus high32 argument bits do not influence this gate. For flag in{0,1}, the computed table index is `0xb6b XOR (effective_flag * 0xbb)`:

| Condition | Index | Original target |
| --- | --- | --- |
| flag0, or extent mismatch | 0xb6b | `0xfffffe000a656f00`, existing common cleanup |
| flag1 and equal extents | 0xbd0 | `0xfffffe000a65ff38`, saved-mode gate |

The publication theorem has an explicit phase cut: C+0x548=&C+0x3c0, X21=&S+0xbe4, callback=`0xfffffe000a65fea8` and W11=0x217. The same return target also occurs at checked table indices0x614,0xd5f and0xe2f; the audit does not derive which incoming serializer phase supplies each index. Allocation, serialization and publication reachability are not inferred from these stores alone.

## Saved-mode branch and reverse byte step

The block at `0xfffffe000a65ff38` compares u32[F+0x5c0] with 0x7c233caf, loads Z from C+0x358, A from C+0x3c0 and counter64 from F+0x5b8. With the callback's proved W9=0xb6b and TOKEN, its parity expression reduces to the following mapping:

| Saved mode | Selected target | Effect within captured boundary |
| --- | --- | --- |
| 0x7c233caf | `0xfffffe000a656f00` | Bypasses byte step |
| Any other u32 | `0xfffffe000a65ff84` | Enters byte step with saved counter64 |

The step's constants satisfy `0xffffffff7795e35c + 0x886a1ca3 = -1 mod 2^64`. Therefore incoming counter T produces j=T-1. Under T>0, disjoint readable/writable extents [A,A+T) and [Z,Z+T), nonwrapping addresses and nominal-pointer guards:

```text
flag1 + M=low32(argument64)
  -> saved mode differs from 0x7c233caf
  -> T -> j=T-1
  -> load A[j] -> remove auxiliary mask -> apply staging mask -> store Z[j]
  -> j!=0: same byte-step entry with counter=j
  -> j==0: common cleanup
```

| Byte/interface PC | Established result |
| --- | --- |
| `0xfffffe000a65ffac` | Forms auxiliary address A+j |
| `0xfffffe000a65ffc0` | Reads one stored source byte |
| `0xfffffe000a65ffc4` | Forms staging address Z+j |
| `0xfffffe000a660038` | Writes one transformed byte to Z+j |
| `0xfffffe000a66003c` | Tests j against zero |
| `0xfffffe000a660050` | Loads index0xb6b if j=0, otherwise0xbbb -> `0xfffffe000a65ff84` |

The local step preserves C/S/table/TOKEN, A/Z bases, both staging keys, the cursor adjustment and W9=0xb6b. The producers below establish initial T=N and mode=N XOR 0x7c233caf. The mode gate therefore bypasses the step iff N=0. For N>0, induction on T establishes exactly N byte steps, indices N-1 through0, and then common cleanup, conditional on intact saved cells, admitted buffer storage and nominal-pointer guards at every step. Native retag alternatives and complete construction-to-callback reachability remain outside that theorem. A zero counter passed directly to the isolated step is outside its premises; the composed zero-length route bypasses it.

## Original producers of mode and counter

| Source location | Source-derived value |
| --- | --- |
| `0xfffffe000a635604` | Loads original argument64 from F+0x878 into X19 |
| `0xfffffe000a635608` | Sets W0=N shifted left1 modulo2^32 |
| `0xfffffe000a63596c`..`0xfffffe000a63598c` | Computes W14=N-((N shifted left1) AND 0xf846795e)+0x7c233caf modulo2^32 |
| `0xfffffe000a63621c` | Stores W14 at F+0x5c0 |
| `0xfffffe000a636220` | XORs W14 with W13=0x7c233caf |
| `0xfffffe000a636224` | Stores zero-extended XOR result64 at F+0x5b8 |

Let K=0x7c233caf; then 0xf846795e=2K. The u32 identity `N-2*(N AND K)=(N XOR K)-K` reduces W14 exactly to N XOR K, and the saved counter to zero-extended N. The source-level proof permits all argument64 values, including arbitrary high32 bits. Between argument load/shift and mode arithmetic, 216 straight-line words do not write X19/W19 or X0/W0. Between mode arithmetic and the saved stores, 547 straight-line words do not write X13/W13 or X14/W14. Both ranges match the original and normalized images and contain no branch/call/trap/return. These retention checks preserve register values; they do not establish native validity of every intervening memory access.

The callback composition restores its separately supplied incoming flag at the analysis cut and assumes the saved frame cells remain intact. It does not model initial setup as a direct fall-through into the much later serializer callback.

## Exact address-dependent byte contract

For an address a, let arithmetic before byte extraction be u64:

```text
mask(a,k0,k1) = byte((ROR64(a AND 0xfffffffffffffff8,8) + k0) XOR k1,
                     a AND7)
```

`byte(x,r)` means bits8r..8r+7, with r in0..7. The recovered key pairs are:

| Storage | k0 | k1 |
| --- | --- | --- |
| Auxiliary | 0xc318995a4ba7c5cd | 0x72cef43cdf673afd |
| Staging | 0x02e859d27e491464 | 0x4dae26df20976138 |

The source uses temporary auxiliary k1=`0x9e2218d0338bd611` and separately XORs the selected byte with 0xec. Their combined key is exactly `0x9e2218d0338bd611 XOR 0xecececececececec = 0x72cef43cdf673afd`. For arbitrary source byte b and admitted addresses, the source-level theorem is:

```text
written_byte XOR mask(Z+j,staging_k0,staging_k1)
  = b XOR mask(A+j,auxiliary_k0,auxiliary_k1)
```

This identifies storage transcoding. It does not establish message encryption, a secret-key protocol, record semantics or native buffer contents. The existing final-copy analysis removes the staging mask before copying to the original caller buffer; end-to-end byte identity still depends on actual serializer output, admitted storage and complete control-flow composition.

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test or falsification probe |
| --- | --- | --- |
| AC-A1: Results apply only to the pinned original/normalized images | AC1-AC7 | Compare complete function hash, every captured word and original pointer target; another build requires recapture |
| AC-A2: Modeled AArch64 u32/u64 load/store, XOR, arithmetic, rotate and register-shift semantics | AC1-AC7 | Arbitrary symbolic extents, high argument bits, mode, counter and stored byte; re-solve all frozen source formulas |
| AC-A3: Selected C/S/F/table roots and ordinary readable/writable nonoverlapping frame/context/workspace | AC1-AC7 | Exact address obligations, nonwrapping/disjoint storage premises and predecessor alias theorem replay |
| AC-A4: Publication cut supplies pointer/extent output aliases, encoded M, saved callback and return index0x217 | AC1 | Source stores/continuation are proved; derive full serializer and all phase indices before asserting unconditional publication |
| AC-A5: Incoming callback W8 is0 or1, encoded extent is M XOR SUCCESS, saved argument channel is intact | AC2, AC3 | Separate flag0/1 formulas, arbitrary M/argument64, exact equality and original counter/mode proofs, intact saved frame cells and an altered-literal SAT counterexample |
| AC-A6: Step has positive T, separate A/Z extents of T bytes, no wrap and nominal-pointer branch guards | AC4-AC6 | Arbitrary counter/byte/address obligations, terminal j=0 branch and root/key preservation; inspect native retag and alias cases separately |
| AC-A7: Serializer output, full serializer-to-callback reachability and native daemon transaction identity remain unknown | AC7 limits | Check saved-cell custody through the complete serializer path, then correlate an observed daemon/provider transaction |

## Bounded continuation and cost

| Impact | Next evidence | Contribution |
| --- | --- | --- |
| High | Saved-cell custody through callbacks and opaque helpers | Preserve the proved N counter/mode basis through complete source effects |
| High | Serializer entry `0xfffffe000a65f3ec`, extent accumulation/allocation and node-copy loop | Establish auxiliary M, bytes and complete publication-to-callback reachability |
| High | Protected record writer and list publication | Connect the three request packets to actual container contents |
| High | Observed daemon request/response bytes, endpoint identity and native transfer counts | Correlate the static ABI with a complete cross-layer transaction |
| Medium | Retag branches, aliasing and buffer ownership | Delimit when the nominal-pointer byte theorem composes with native storage |
| Low | Similar mask pairs elsewhere | Candidate storage-format family; numerical resemblance alone does not identify a protocol |

Each captured gate/byte step takes O(1) work and O(1) state. Conditional repetition from the proved initial N>0 has N byte steps and O(N) work, excluding allocation, serialization and cleanup; N=0 bypasses the loop. Extraction uses O(B+I) time/space for consumed image bytes B and selected instructions I; proof construction uses O(instruction instances+query DAG), with SMT search separately limited to30 s/query. Extents count bytes (B); widths are exact u32/u64 and arithmetic wraps modulo2^32/2^64 as indicated.

## Quality gates

- **QG1**: Claims are factual source/data/control/ABI analysis.
- **QG2**: AC-A1-AC-A7 identify dependencies and falsification probes.
- **QG3**: This increment covers auxiliary publication, original counter/mode derivation, extent/flag dispatch and conditional N-byte reverse transcoding; the full interface goal remains active.
- **QG4**: Widths, byte extents, key reduction, counter decrement, complexity and modeled/excluded word counts are explicit.
- **QG5**: Conditional publication, private flag/mode, extent equality, positive step counter, native effects and whole-loop reachability remain distinct.
- **QG6**: Dual-image capture, eight original pointers, 12 nonvacuous source formulas, one predecessor recheck, 698 instruction instances, 763 structural instances and the SAT control support the stated contracts.
- **QG7**: Ranked continuation includes saved-state custody, serialization, record publication, transaction correlation, pointer environment and bounded mask-family candidates.


The [serializer extent contract](userclient_serializer_extent_report.md) now establishes checked node-extent accumulation, strict 16 B padded sizing, the original allocator ABI and encoded extent custody. Under the stated successful-publication cut, the original consumer admits copying only when the request length equals that padded allocation extent. Node/padding emission, container stability across passes and native transaction pairing remain unknown; no additional Mach port endpoint is established.


The [serializer emission contract](userclient_serializer_emission_report.md) now closes conditional finite stable-list emission: decoded node-byte concatenation, terminal tag0/type50db/big-endian padding length, exact zero payload, and output pointer/extent publication with flag1/raw SUCCESS. The terminal shape normalizes to the recovered parser type0x6685. Original metadata-node construction, native list/storage validity and daemon transaction pairing remain unknown; no additional Mach endpoint is established.
