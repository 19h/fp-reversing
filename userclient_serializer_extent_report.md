# Auxiliary serializer extent and allocation contract

The auxiliary producer sums node extents with an exact unsigned 32-bit overflow gate. For final node-byte sum L, it derives padding P=16-((L+10) AND 15) and requests M=L+10+P bytes from `_IOMallocData`. Thus M is the first multiple of 16 strictly greater than L+10. The source accepts exactly L<=0xffffffe5, giving 16<=M<=0xfffffff0. The selected copy setup encodes that same M for the downstream consumer; a source-composed successful callback admits copying only when low32(original argument64)=M. The linked [emission report](userclient_serializer_emission_report.md) now establishes conditional node-byte emission and output publication; native allocation/list validity and daemon pairing remain unknown.

## Evidence and claim register

The [extractor](triage_evidence/recover_userclient_serializer_extent.py), [instruction audit](triage_evidence/audit_userclient_serializer_extent.py), [delivery verifier](triage_evidence/verify_userclient_serializer_extent_delivery.py), [checks](triage_evidence/userclient_serializer_extent_checks.json.zst) and [proofs](triage_evidence/userclient_serializer_extent_audit.json.zst) retain original source bytes, pointers, formulas and boundaries. Primary sources are the original kernel collection and normalized kext. Predecessors cover [query records](userclient_query_records_report.md), [auxiliary publication and N-byte transcode](userclient_auxiliary_copy_report.md), [core copy-back/return](userclient_caller_return_report.md) and [provider transfer ordering](userclient_transfer_boundary_report.md).

| Claim | Established result | Dependencies |
| --- | --- | --- |
| SE1 | Entry saves the auxiliary pointer-output alias and callback, clears its internal allocation cell, initializes padding control and selects null/non-null container frontiers with flag0 | SE-A1-SE-A3 |
| SE2 | Each selected node step rejects sum overflow, otherwise adds the exact node extent and follows its next link; null head/successor select size finalization | SE-A1-SE-A4 |
| SE3 | Padding is 1-16 B; M is strictly greater than L+10 and divisible by 16; accepted L and M have the exact bounds above | SE-A1-SE-A4 |
| SE4 | The original S bank selects `_IOMallocData`, IA diversity0xca0c, with zero-extended X0=M | SE-A1-SE-A5 |
| SE5 | The allocator result is saved in C+0x198; null returns with flag0, nonnull selects copy setup; raw status is reloaded from its saved channel | SE-A1-SE-A5 |
| SE6 | Copy setup derives encoded M XOR SUCCESS and node/padding frontiers; under the declared publication cut, the actual consumer admits copying only for original N=M, requiring N>=16 and N divisible by16 | SE-A1-SE-A6 |
| SE7 | Nine spans, 386 instruction locations, 15 nonvacuous source queries, three predecessor rechecks, 256 bank cases and 16 residue profiles support the bounded contract | SE-A1-SE-A7 |

Normalized image SHA-256: `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Original collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. All 386 selected words and nine separately captured terminal transfers match both images. Fifteen original chained branch pointers and the allocator's original pointer are checked against normalized targets. Original authentication metadata is evidence of pointer encoding, not a native PAC authentication result.

Decoded checks SHA-256: `f962f20903ac8c47e92a284e801bcfd32513415cf388a15f44348d32d86f2f4b`. Decoded audit SHA-256: `429b9f0944fcad4163d4f48cdfd6e0c889b62bc86cd004545025e5c53bd1e8de`. The 15 source queries cover 2,040 instruction instances. The 16 finite residue profiles are additional checks and are excluded from that proof-instance count. A changed padding literal produces a SAT counterexample. No target execution, IDB mutation or new live IDA observation supplies this increment.

The selected blocks lie inside original routine `_PRnut72j9`, `0xfffffe000a635208`..`0xfffffe000a666930` exclusive, 50,634 instruction words, complete containing-range SHA-256 `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297`. The retained C export identifies that name at line199131. The serializer labels describe internal blocks; complete semantics of the containing obfuscated routine remain unresolved.

## Entry, roots and control flow

F denotes the selected frame SP, C the context, S the workspace, H the container, J a node and A the auxiliary allocation. `TOKEN=0x886a1ca3`, `PHASE=0x7795e642`, `SUCCESS=0x31ae0066`, `PAD_BASE=0x1aad43d4`. Pointers and saved argument/counter channels are u64; node extents and phase/control values are u32.

| Entry input / stored channel | Exact role |
| --- | --- |
| X11=&C+0x600 | Loads H into X25 |
| X12=&C+0x3c0 | Saved at C+0x548 as the auxiliary pointer-output cell |
| X21=&S+0xbe4 | Retained encoded auxiliary extent-output cell |
| W9=0x161 | Selects callback `0xfffffe000a65fea8`, saved at C+0x468 |
| W25=TOKEN, W10=PHASE | Derive the selected entry phase |
| C+0x198 | Cleared before allocation; later receives returned A |
| S+0xb40 | Initially PAD_BASE; later becomes PAD_BASE+P |

The following original table mappings are retained. Table indices are private control-flow selectors, not Mach message identifiers or user-client selector numbers.

| Source dispatch | Condition / index | Original target |
| --- | --- | --- |
| `0xfffffe000a65f430` | H null /0xe2f; H nonnull /0xe10 | Saved return `0xfffffe000a65fe98`; head `0xfffffe000a65f448` |
| `0xfffffe000a65f488` | Head null /0x5e2; head nonnull /0x5c7 | Size `0xfffffe000a65f5e4`; extent `0xfffffe000a65f494` |
| `0xfffffe000a65f56c` | Sum overflow /0xd5f; fits /0xd82 | Saved return `0xfffffe000a65fe98`; advance `0xfffffe000a65f580` |
| `0xfffffe000a65f5d8` | Next null /0x5e2; next nonnull /0x5c7 | Size `0xfffffe000a65f5e4`; extent `0xfffffe000a65f494` |
| `0xfffffe000a65f6ec` | Total rejected /0x217; accepted /0x237 | Saved return `0xfffffe000a65fe98`; allocation `0xfffffe000a65f700` |
| `0xfffffe000a65f900` | Allocation null /0x614; nonnull /0x60a | Saved return `0xfffffe000a65fe98`; copy setup `0xfffffe000a65f910` |
| `0xfffffe000a65f94c` | Head null /0x2a7; head nonnull /0x35a | Padding emission `0xfffffe000a65f9a8`; node-copy gate `0xfffffe000a6600ac` |
| `0xfffffe000a65fef8` | Successful published M differs from original N /0xb6b; equal /0xbd0 | Common cleanup `0xfffffe000a656f00`; mode gate `0xfffffe000a65ff38` |

The null-container entry leaves flag0 and raw status0xce515bbf. Node-sum and total-size rejection leave flag0 and raw status0xce515bb8. After the allocator returns, the source reloads the separate raw-status cell F+0x9ec; the audit permits any saved u32 status and does not assign a hard-coded allocation-failure code. The predecessor callback honors flag0 regardless of extent equality.

## Node-extent accumulation and strict padded size

The head block initializes accumulator u32 L=0 and loads H's first pointer. The selected node step loads u32[J+0x10] as E. Its obfuscated comparison is exactly the following unsigned test, evaluated at 64-bit width in the specification:

```text
if zero_extend64(L) + zero_extend64(E) >= 2^32:
    return with flag0
L = L + E
J = u64[J+0]
if J !=0: repeat node-extent step
otherwise: finalize size
```

The source tests before the addition. For an admitted finite chain of valid nodes, induction therefore establishes L=sum(E_i) without u32 wrap, or rejection at the first overflowing prefix. This does not establish that every native chain is finite or that the container is unchanged between passes. Zero-sized nodes are included in the arbitrary-extent step proof.

The size block `0xfffffe000a65f5e8`..`0xfffffe000a65f6fc` reduces exactly to:

```text
r = (L +10) AND15
P =16 -r                         # 1 <= P <=16 bytes
u32[S+0xb40] = PAD_BASE +P        # additive encoding
M64 = zero_extend64(L) +10 +P
accept iff M64 <2^32
```

Although r uses u32 addition, only the low four bits are consumed; the wide M64 expression retains the full sum. The source's final comparison is `L+P <0xfffffff6` at u64 width, equivalent to M64<2^32. It is not a wrapping u32 extent test.

| Node-byte sum L (B) | P (B) | M (B) | Gate result |
| --- | --- | --- | --- |
| 0 | 6 | 16 | Accept |
| 5 | 1 | 16 | Accept |
| 6 | 16 | 32 | Accept |
| 15 | 7 | 32 | Accept |
| 28 | 10 | 48 | Accept |
| 0xffffffe5 | 1 | 0xfffffff0 | Accept, largest L |
| 0xffffffe6 | 16 | 0x100000000 | Reject |
| 0xffffffff | 7 | 0x100000010 | Reject |

Thus M=16*(floor((L+10)/16)+1), with the floor expression interpreted in integers. Already-aligned L+10 receives a full 16 B of padding. An empty nonnull container reaches the allocator with exactly16 B and P=6 B; null H instead takes the entry's saved-return edge. The universal formulas cover all u32 sums, while the retained 16 finite profiles exercise every low-four-bit residue independently of the SMT proof.

## Allocation target, extent custody and consumer admission

The request mixer derives W20=M XOR0x18b18db2. The final argument assignment XORs that constant away into W0, zero-extending the accepted size into X0. The source requests exactly M bytes, not the encoded control word or node-byte sum L.

| Interface | Original source / exact result |
| --- | --- |
| Left bank | `0xfffffe0007941f60`, selected via F+0xa50 |
| Right bank | `0xfffffe000794a0d0`, selected via F+0xa58 |
| Bank rule | Key0x05, exhaustive byte relation `j XOR R[L[j] XOR5]=0x2d` |
| Table selection | 0x2d+0xee3=0xf10 |
| Original pointer slot | `0xfffffe000847a7a0` |
| Target | `0xfffffe000c4ba60c`, exact original symbol `_IOMallocData` |
| Call PC | `0xfffffe000a65f8b0`, IA diversity0xca0c, X0=M |
| Result store | `0xfffffe000a65f8e8`: saves returned X0 at C+0x198 |
| Result dispatch | `0xfffffe000a65f900`: null -> saved return; nonnull -> copy setup |
| Size encoding | `0xfffffe000a65f920`: W28=W20 XOR0x291f8dd4=M XOR SUCCESS |

Both controller snapshots at original globals `0xfffffe000ccc30d0` and `0xfffffe000ccc32f8` are arbitrary in the call proof. With the pinned bank bytes, their effect on the selected byte is canceled by the exhaustive bank relation; they cannot change this selected allocator target within the modeled phase. This is a local target-selection result, not a claim about all indirect calls or mutable native bank storage.

The allocator model havocs caller-saved registers, admits any returned pointer value and preserves the declared private frame/context roots. The result block restores C/S/table/TOKEN/SUCCESS and saves the returned pointer. A nonnull value proves selection of the copy frontier; it does not prove that native storage of size M exists or that allocation/site ownership is valid.

The selected copy setup initializes cursor32=0, reloads H's head and installs key0 constants `0x02e859d27e491464` and `0xc318995a4ba7c5cd`. These match the earlier staging and auxiliary mask families, respectively. Header/payload byte effects of the node-copy frontier and padding emission remain outside this increment. In particular, matching constants alone are not a proof of emitted bytes.

```text
H -> checked node-byte sum L -> strict padding P -> request M=L+10+P
  -> saved allocation C+0x198 and encoded extent M XOR SUCCESS
  -> node-copy or padding frontier
  ... emission and complete publication path remain unproved ...
  -> successful publication cut -> original consumer compares M with N
  -> M=N: copy-mode gate -> conditional N-byte transcode
  -> M!=N: common cleanup
```

The composition proof runs the actual request/result/copy-setup instructions, takes the publication congruence cut rechecked from the predecessor, then runs the actual consumer callback at `0xfffffe000a65fea8`. At that cut it transfers the derived W28 into S+0xbe4 and supplies successful flag1. This does not silently execute the unresolved emission path or infer its success.

| Source-composed condition | Established consequence |
| --- | --- |
| Accepted allocation size and successful publication | Encoded extent consumed by the callback equals M XOR SUCCESS |
| Consumer enters its copy-mode gate | N=low32(original argument64)=M |
| Same admitted copy route | N divisible by16 and 16<=N<=0xfffffff0 |
| N=0 on this successful serializer route | M>=16, so extent mismatch selects cleanup before the copy-mode gate |

The predecessor's zero-counter mode branch remains a valid isolated consumer theorem. This successful serializer cannot supply M=0, so that particular composed N=0 case reaches the earlier mismatch edge. No contradiction is resolved by changing either predecessor result.

The publication cut and ordinary private-cell custody remain explicit premises. Native allocator effects, capacity of A, stable node extents/data across passes, native retag paths, opaque helper memory effects and a matching observed fairplayd transaction remain unknown. The provider's transfer count/status behavior is established in its separate report; this sizing theorem does not establish actual native copy counts or response bytes.

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test or falsification probe |
| --- | --- | --- |
| SE-A1: Results apply only to the pinned original/normalized images and fixed pointer banks | SE1-SE7 | Compare complete containing-function hash, every selected word, both 256 B banks and original chained pointer metadata |
| SE-A2: Modeled AArch64 u32/u64 operations, unsigned comparisons, loads/stores and ordinary register behavior | SE1-SE7 | Re-solve every frozen source formula; arbitrary sum/extent/controller/status/argument values; changed padding literal must refute the expected identity |
| SE-A3: Selected C/S/F/table roots and separate ordinary readable/writable frame, context4096 B, workspace16384 B, H16 B and admitted J32 B | SE1-SE7 | Original root/cell aliases and exact address obligations; null H/head/result cases remain separate; native pointer validity is not inferred |
| SE-A4: Repeated extent-step composition has valid nodes, a finite chain, appropriate phase constants and final L equal to its accumulated sum | SE2, SE3, SE7 | Universal single-step overflow/add/next-link proofs and empty-head composition; inspect cycles and node mutations before asserting native termination or list stability |
| SE-A5: Allocator returns normally under ordinary ABI and preserves declared callee-saved/private roots, including H and saved status | SE4-SE7 | Volatile-register havoc, arbitrary return pointer and raw saved status, exact null/non-null frontiers; actual allocation size, ownership and helper memory effects remain unknown |
| SE-A6: Emission reaches successful publication with the derived encoded M and intact original argument/output cells | SE6, SE7 | Rechecked predecessor publication/callback formulas and source-composed consumer; recover complete node/padding emission and publication before asserting whole-path reachability |
| SE-A7: Serialized bytes, complete list/source effects, native daemon transaction identity and new Mach endpoint meaning remain unknown | SE7 limits | Establish emitted records, snapshot/locking context and observed endpoint/selector/request/response pairing independently |

## Bounded continuation and cost

| Impact | Next evidence | Contribution |
| --- | --- | --- |
| High | Node-copy frontier `0xfffffe000a6600ac` and padding frontier `0xfffffe000a65f9a8` | Convert allocation and extent custody into exact emitted bytes |
| High | Complete successful emission-to-publication path | Discharge the current congruence cut before claiming end-to-end serializer behavior |
| High | H/node extent/data stability between the sizing and emission passes | Establish the snapshot, ownership or synchronization contract required for native capacity reasoning |
| High | Protected metadata writer and node-list publication | Connect the three private query requests to actual container records |
| High | Observed daemon/provider endpoint, selector, transfer counts and request/response bytes | Correlate this selected ABI with an actual cross-layer transaction |
| Medium | Container finiteness, allocator ownership, PAC and pointer retags | Establish termination and native environmental premises rather than extending a one-step proof |
| Low | Other occurrences of the strict padded-size and extent-encoding identities | Locate candidate shared serialization interfaces, requiring independent source confirmation |

Each captured gate, allocation request and node step has O(1) local work/state, excluding native allocator cost. For a finite k-node list, the selected sizing pass has O(k) work and O(1) state; no termination bound is asserted for an arbitrary cyclic chain. This pass computes M and requests that many bytes; complete emission complexity remains outside scope. The predecessor conditional copy has O(N) work for its proved initial N. Extraction uses O(B+I+256R) time/space for consumed image bytes B, instructions I and bank rules R. Proof construction uses O(instruction instances+query DAG); SMT search is separate with30 s/query limits. All extents count bytes (B); arithmetic wraps at the stated u32/u64 widths, and wide admission formulas explicitly avoid u32 truncation.

## Quality gates

- **QG1**: Claims are factual source/data/control/ABI analysis.
- **QG2**: SE-A1-SE-A7 state dependencies and falsification probes.
- **QG3**: Entry, node-sum overflow, strict padded size, allocator ABI/result custody, copy setup and source-composed consumer admission are covered; the full interface goal remains active.
- **QG4**: u32/u64 widths, byte extents, positive padding, largest accepted/rejected sums, encoded size, proof/profile counts and complexity are explicit.
- **QG5**: Null container versus empty list, raw status versus flag, strict versus ordinary rounding, encoded extent versus allocation bytes, isolated zero counter versus this producer's positive M, and congruence cut versus complete execution remain distinct.
- **QG6**: Dual-image capture, 15 original branch pointers, allocator symbol/authentication metadata, 15 nonvacuous source formulas, three prior rechecks, 256 bank cases, 16 residue profiles, 2,040 proof instances and the SAT control support the bounded contract.
- **QG7**: Ranked continuation covers emission/publication, container snapshot context, metadata records, transaction pairing, environment and bounded shared-format candidates.


The [serializer emission contract](userclient_serializer_emission_report.md) now closes conditional finite stable-list emission: decoded node-byte concatenation, terminal tag0/type50db/big-endian padding length, exact zero payload, and output pointer/extent publication with flag1/raw SUCCESS. The terminal shape normalizes to the recovered parser type0x6685. Original metadata-node construction, native list/storage validity and daemon transaction pairing remain unknown; no additional Mach endpoint is established.
