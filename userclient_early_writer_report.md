# Early protected-header composition with arbitrary setup cells

Subsequent early-payload evidence: The [early payload report](userclient_early_payload_report.md) conditionally completes u32/u64 and plaintext-span serialization through the common continuation. Fifteen new source proofs, two header rechecks, 30 premise-checked partial-state evaluations, 468 serialized bytes and three rejected mutations pass. Seven source-defined cells per case have overlapping-store custody. Scalars require exact four/eight-byte lengths; zero spans bypass payload access and nonzero spans copy plaintext into protected destination bytes. Eight unrelated setup cells remain symbolic; native admission, continuous guest extension, publication and daemon/kext identity remain unknown. Earlier boundaries below retain their historical scopes.

The early non-NULL data-result path conditionally writes the exact ten-byte protected header `BE32(D) || BE16(V) || BE32(L)` into its current record buffer. Its record comes from `C+0x58`. All eight previously unknown setup cells remain independent symbolic values. Varying those values changes neither the ten header bytes, the addresses of all 25 source loads and 15 source stores, nor the targets and modifiers of seven logical transfers on this composed path. Scratch values may change.

This refines the distinction between syntactic definedness and semantic dependence in the [data-return report](userclient_early_data_report.md). The continuous private execution still stops before the undefined load at `0xfffffe000a654ae4`. No missing value was filled, no guest execution was continued beyond that boundary, and no native initialization or complete serialization has been established. The result is a conditional composition of original instructions under the explicit storage and pointer premises below.

## Primary evidence and custody

| Evidence | Identity or bound |
| --- | --- |
| Kernel collection SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Full `_PRnut72j9` container | `[0xfffffe000a635208, 0xfffffe000a666930)`, 202536 bytes, 50634 words |
| Container SHA-256 | `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297` |
| Decoded checks SHA-256 | `759215006af5fe74e734b270d0e64e6b80e5973963a33074a2dab93872cf8ddf` |
| Decoded audit SHA-256 | `07d13d8e0b1a89a40028bbff209460a49c33e8fb2a7eb5973244446be95f76d8` |
| Source capture | Six spans, 227 original words; original and normalized bytes agree |
| Main composition | 309 instruction instances, 223 distinct PCs; four alternate MOVK words checked separately |

The [generator](triage_evidence/recover_userclient_early_writer.py) freezes bytes, authenticated-table pointer records and 30 predecessor handoffs. The [auditor](triage_evidence/audit_userclient_early_writer.py) independently lifts the captured instructions into fixed-width bit vectors. The [delivery verifier](triage_evidence/verify_userclient_early_writer_delivery.py) regenerates both receipts, compares canonical SMT expressions and verifies publication custody. Receipts are [checks](triage_evidence/userclient_early_writer_checks.json.zst) and [audit](triage_evidence/userclient_early_writer_audit.json.zst); hashes above refer to decoded JSON bytes. No live IDA database was required or modified for this increment.

## Claim register

| Claim | Established result and evidence boundary |
| --- | --- |
| EW1 | The data return is stored at `J+0x18`; the non-NULL edge selects the early writer preparation. Original-source proof; no allocator behavior inferred. |
| EW2 | Handoff carries the pointer-cell address `J+0x18`, tag channel, workspace/context and early phase `0x13c`. Thirty predecessor projections agree. |
| EW3 | Shared setup retains `C+0x58` as the current record despite loading eight arbitrary other cells. No initialization claim for those cells. |
| EW4 | Two common word-writer invocations and the early type writer produce exactly ten protected bytes for raw tag, type and length. Conditional normal-pointer path. |
| EW5 | Two-world proof establishes header, memory-address and selected-transfer independence from the eight unknown cells. Scratch-value independence is not claimed. |
| EW6 | Thirty partial-state evaluations match 330 projected handoff register values and 300 independently encoded header bytes; zero unknown-cell bindings. These are not native or continuous guest executions. |
| EW7 | Fourteen new source obligations and three retained reader obligations are UNSAT with satisfiable new-proof premises. Two mutated sources are rejected by the normal oracle. |
| EW8 | Early and later phases share code but select different record/type/length channels and continuation indices. No new Mach endpoint, full payload or native daemon/kext identity follows. |

## Phase-specific interfaces

`C` denotes the private context, `S` the workspace, `J` the current 32-byte node, `Z` its data buffer and `F` the stack-frame base. `D`, `V` and `L` are the raw 32-bit tag, 16-bit wire type and 32-bit length. `SUCCESS = 0x31ae0066`. Previous node allocation/zeroing and `J+0x10 = L+10` are inherited contracts, not new native allocator conclusions.

| Interface | Early phase, this proof | Later phase, prior reports |
| --- | --- | --- |
| Selected node | `C+0x58` | `C+0x6b8` |
| Buffer cell | `X8 = J+0x18` | `X10 = later_node+0x18` |
| Type channel | `S+0x1b2`, `Ue = V XOR 0xa2e3` | `S+0xb90`, `Ul = V XOR 0x365e` |
| Length channel | `S+0x94`, `L XOR SUCCESS` | `S+0xe28`, `L XOR SUCCESS` |
| First word continuation index | `0x13c`, early type writer | `0x152`, later type writer |
| Second word continuation index | `0x165`, early type gate | `0x16c`, later type gate |
| Word-writer selection | Immediate `W25 = 0x439` | Saved frame channel masked to `0x439` |

Later-phase claims retain the scope of the [record writer](userclient_record_writer_report.md) and [record nodes](userclient_record_nodes_report.md) evidence. Equality of the raw type implies `Ul = Ue XOR 0x94bd`; equality of the encoded channels is neither required nor asserted. In this receipt `0x16c` is inherited context, not a newly captured table entry.

The eight free setup cells are 64-bit roots `C+0x768`, `C+0x458`, `C+0x140`, `C+0x6b8`; 32-bit metadata `S+0xd30`, `S+0xe28`, `S+0xdf8`; and 16-bit type `S+0xb90`. Their eager loads explain the earlier 46-byte private-definedness gap. They are not dereferenced as object roots on this selected header path. Their values can be copied into scratch state, so the theorem does not erase their relevance to subsequent phases.

## Source sequence and protected bytes

All addresses in this sequence are original virtual PCs, not execution observations on native hardware.

| Transfer PC | Selected target | Modifier |
| --- | --- | --- |
| `0xfffffe000a66187c` | `0xfffffe000a661880` | `0x3769` |
| `0xfffffe000a6618e8` | `0xfffffe000a654ad4` | `0xdfc5` |
| `0xfffffe000a654b94` | `0xfffffe000a654c64` | `0x682a` |
| `0xfffffe000a654dc8`, first invocation | `0xfffffe000a654fc8` | `0x3aa3` |
| `0xfffffe000a655064` | `0xfffffe000a654c44` | `0x8165` |
| `0xfffffe000a654c60` | `0xfffffe000a654c64` | `0x682a` |
| `0xfffffe000a654dc8`, second invocation | `0xfffffe000a654dcc` | `0x3aa3` |

```text
data return -> retain Z in J+0x18 -> early preparation
  -> shared setup -> tag32 writer -> early type16 writer
  -> length bridge -> length32 writer -> early type gate
                    Z[0..3] Z[4..5] Z[6..9]
```

The common byte-store PCs are `0xfffffe000a654ccc`, `0xfffffe000a654d18`, `0xfffffe000a654d74` and `0xfffffe000a654db0`, executed twice. Early type bytes are stored at `0xfffffe000a655014` and `0xfffffe000a655038`. The second word invocation ends at the early type gate; payload-specific processing beyond that gate is outside this proof.

For unsigned address `a`, let `ROR64` rotate a 64-bit word right and all additions wrap modulo `2^64`:

```text
K0 = 0x02e859d27e491464
K1 = 0x4dae26df20976138
plain = BE32(D) || BE16(V) || BE32(L)
mask8(a) = low8(((ROR64(a AND ~7, 8) + K0) XOR K1)
                >> (8 * (a AND 7)))
for j = 0..9:
    Z[j] = plain[j] XOR mask8(Z + j)
```

The exact output is ten bytes, not a plaintext memory image. The address-dependent mask is evaluated using the destination byte address. Applying the same mask recovers the raw fields; the three existing protected-header reader queries were independently re-solved. This algebraic compatibility does not establish a matched native transaction or identify a producer in fairplayd.

The main path contains eight normal-pointer branch instances at four unique retag decisions. Four additional proofs establish only the alternative MOVK bit transform: replacement of bits 63..48 with `0xc8a2`, preserving bits 47..0. They do not establish alias validity, accessibility or equivalence for such retagged pointers. Logical transfer targets/modifiers are checked against original table-pointer records; native PAC authentication is not performed.

## Independent checks and mutation controls

The fourteen new obligations comprise ten path/interface/output/independence obligations and four alternate-MOVK bit-transform obligations. They account for 2305 lifted instruction instances across queries. All new premises are checked satisfiable before negating the claimed property. The independent two-world models share live inputs/storage addresses while assigning separate unconstrained symbols to all eight missing cells and unrelated entry registers. They compare ten header values, all 25 load addresses, all 15 store addresses and seven target/modifier pairs. They do not compare all register or scratch-memory values.

The thirty retained non-NULL data-result cases cover the predecessor profiles, controller fixtures and placements. Each evaluation binds only known live addresses and fields; it leaves all eight missing cells, and the irrelevant status value, unbound. Eleven projected handoff register expressions per case equal the predecessor receipt. Ten source-derived byte expressions per case become concrete and match an independent Python implementation of big-endian encoding and the rotate/mask formula. This establishes consistency of the conditional composition with those partial states, not actual writes beyond the stopped boundary.

| Copied-source mutation | Observed oracle rejection |
| --- | --- |
| NOP replaces type store at `0xfffffe000a655014` | Only nine header stores remain; ten-byte output contract fails. |
| NOP replaces modifier setup at `0xfffffe000a654dc4` | Ten-byte header remains universally correct, but a satisfiable path has an incorrect selected transfer modifier. Control-interface oracle fails. |

Both mutated paths have satisfiable storage/branch/table premises. Only copied symbolic source is mutated; original images and IDBs are unchanged. These controls test the byte and logical control contracts separately. Neither tests native PAC behavior.

Construction cost is linear in captured instruction instances, query-expression DAG size and retained-case expression evaluation; solver search cost is separate and bounded to 30 seconds per query. Receipt reconstruction additionally reads and hashes the frozen full container and predecessor evidence. There are no physical time, size-of-object or native throughput measurements inferred from solver execution.

## Assumption register and falsification probes

| Assumption | Dependencies and stress test |
| --- | --- |
| EW-A1: Image identity and normalization | EW1-EW8. Rehash original collection, full container and normalized source; compare every captured byte and selected table-pointer record. Any mismatch invalidates reuse. |
| EW-A2: Live predecessor contract | EW1-EW6. Rebuild the 30 predecessor projections and node fields; a differing root, phase, data return or header field invalidates the corresponding composition. |
| EW-A3: Separate owned storage epochs | EW1-EW6. Require nonzero, nonwrapping, pairwise-disjoint F/C/S/J/Z extents, disjoint from image segments, with 16-byte aligned F. Aliasing or expired storage falsifies applicability to a native state. |
| EW-A4: Buffer extent and length | EW4-EW6. Require ten writable bytes at Z and `L <= 0xfffffff5`; no larger native allocation is inferred. Overflowing L or inaccessible Z falls outside the premise. |
| EW-A5: Selected normal-pointer branches | EW4-EW6. Check branch premises satisfiable and normal guards at each of eight instances. Native alternate-pointer behavior requires separate evidence; MOVK transform proofs do not supply it. |
| EW-A6: Instruction/table semantics | EW1-EW7. Independent fixed-width lift, original pointer membership and negative controls probe source/control errors. Native PAC, allocator side effects and concurrency remain unknown. |
| EW-A7: Projection and phase scope | EW5-EW8. Vary all eight missing cells in two worlds; compare stated outputs/addresses/edges. Extend through the early type gate before asserting payload, list publication, other-phase independence or a complete operation. |

## Bounded continuation

| Impact | Next evidence and resulting distinction |
| --- | --- |
| High | Recover early type-specific u32/u64/span payload paths beyond `0xfffffe000a654dcc`; distinguish a ten-byte header theorem from complete record serialization. |
| High | Establish native caller epochs, storage admission and pointer authentication for the selected roots/buffer; determine whether the symbolic premises hold in an actual operation. |
| High | Trace the other eight setup cells in their consuming phases; current header independence does not establish their initialization or later irrelevance. |
| Medium | Recover the original `S+0x20` marker producer and its state transitions; it remains unknown and unread by this header composition. |
| Medium | Pair daemon and kext message/selector evidence from a matched native transaction; this increment identifies no new Mach port or emission location. |

## Quality gates

- **QG1**: Technical source/ABI evidence; no normative premise.
- **QG2**: EW-A1 through EW-A7 identify dependencies and falsification probes.
- **QG3**: Header source, phase selection, arbitrary-cell independence, custody, controls and remaining interface limits are covered.
- **QG4**: Fixed widths, modulo arithmetic, byte order, ten-byte extent and query/case counts are explicit and reproducible.
- **QG5**: Conditional source composition and the unchanged continuous-execution barrier are consistent; scratch, native and later-phase claims remain bounded.
- **QG6**: Original/normalized byte equality, full-container hashes, pointer records, predecessor custody and rebuilt SMT receipts support the claims.
- **QG7**: Continuations are impact-ranked and limited to unresolved native, payload, phase and transaction interfaces. The broader investigation remains active.
