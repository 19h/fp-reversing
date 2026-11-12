# CoreFP canonical workspace construction and separate preparation input

Subsequent evidence: the [consumer network](corefp_workspace_consumers_report.md) resolves ten substitution layers and 36 canonical XOR offsets; the [output-packing report](corefp_output_packing_report.md) joins its sixteen results to the output stores through a fixed affine byte transfer in eight captured domains. Upstream input/preparation fields and native interface admission remain unresolved.

The two 256-word workspaces in original `0x1af6b8` are different encodings of one fixed byte permutation and a fixed affine word expansion. A compact model reconstructs all 3072 workspace words in six fresh complete caller profiles. A source lift of all 36 constructor instructions proves both store values and addresses over arbitrary register/load-interface inputs. Five retained parameter classes normalize to byte rotations and invertible triangular maps.

The separate 16 B preparation source is now distinct from the message, output and context buffers. Ramp/zero/one-byte controls show an exact first-block XOR difference in the retained outputs; the 32 B comparison preserves the second block. These are finite output observations. They do not establish a general chaining mode, complete cipher, public input type, native admission or daemon/kext pairing. The full investigation remains active.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_workspace.py), [checks archive](triage_evidence/corefp_workspace_checks.json.zst), [independent auditor](triage_evidence/audit_corefp_workspace.py), [audit archive](triage_evidence/corefp_workspace_audit.json.zst) and [publication verifier](triage_evidence/verify_corefp_workspace_publication.py) retain the evidence. The preceding [transform report](corefp_pool_transform_report.md), [caller report](corefp_pool_caller_report.md) and [pool allocator report](corefp_pool_allocator_report.md) remain the authorities for local records and lifetimes.

CoreFP arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. Addresses are preferred-base-zero offsets; lengths are bytes (B), with u8/u16/u32/u64 widths explicit. Complete caller, allocator and retirement bodies total 59120 B. Every executed instruction, reaching authenticated row and touched initial/final RAM page is checked against original source and declared fixtures.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| WS1 | Pinned file/fixups, compiler bounds and frozen readers identify the source. All source claims depend on them. | Compare the complete three bodies, dependencies, all executed bytes and original source tables; preserve the three supplied inputs. Complete body retention is not full branch execution. |
| WS2 | The 48 B record, selector 1, empty pool, private context and declared malloc return apply. Complete private paths depend on these premises. | Reconstruct six initial CPU/RAM states; retain original entry, child records and return chain. Check clobber, both extents and nonzero retirement. Native initialization and reachability remain unknown. |
| WS3 | Preparation bytes use a separate valid 16 B buffer. Preparation/output observations depend on that separation. | Move record+`0x10` to `0x64000300`; preserve message/context bytes. Test ramp, zero, byte-0 XOR `0x80`, 16/32 B messages and volatile clobber. Do not generalize the observed output relation without a full transform proof. |
| WS4 | Constructor memory loads are explicit typed interfaces at their original epochs. Straight-line proofs depend on those interfaces. | Lift all 36 instructions; prove both input-table addresses and both stores for arbitrary u32 register/load values and arbitrary u16 table data. Actual profiles verify the disjoint source tables, stack parameters and destinations. Aliasing native objects is outside this loop contract. |
| WS5 | The retained five parameter classes remain invariant across each 256-iteration loop. Canonical full-array reconstruction depends on those phase bindings. | Capture live replay frames at all 1536 loop entries, compare invariant registers/stack cells, check counters 0..255 and every store. Prove each index/word rotation reduction and general triangular inverses. |
| WS6 | Fixed source tables and all 256 entries support the canonical permutation/affine relation. Component classification depends on that complete finite domain. | Check all 256 table entries and all reconstructed words; enumerate the differential table and a precisely bounded standard-reference family. These properties do not identify the whole transform. |

## Separate preparation plane [WS1-WS3]

Entry record+`0x10` points directly to the preparation source. The new fixtures place it at `0x64000300`, separate from message `0x64000100`, destination `0x64000200`, backing arena `0x64002000` and context `0x64004000`. The original source consumes exactly 16 preparation bytes and writes the stack interval `[0x62017f68,0x62017f78)` in descending address order at `0x1afd34`. The child allocation record starts immediately after that interval, at `0x62017f78`.

For i=0..15, source arithmetic and original table bytes give:

```text
prepared[i] = input[i] XOR P[i]
P[i] = low8(95*i XOR A[i] XOR B[i] XOR C[i] XOR 0x64)
P[0..15] = 9c 5d dd 03 67 90 f6 8b f4 7b db 66 58 5c ad 41
```

| Original source read | Sixteen source bytes begin at |
| --- | --- |
| `0x1afcf8` | `0x1ab4186` |
| `0x1afd0c` | `0x1ba8a54` |
| `0x1afd24` | `0x18b1ec1` |

A universal source data-slice obligation proves the byte equation over arbitrary input/table bytes and u32 index. Actual loop reads establish the original table/address bindings in every retained profile. All `16*256=4096` index/input-byte cases are enumerated. At complete return, the prepared stack bytes equal their constructed values and the separate input equals its initial value.

| Preparation / message control | Complete output |
| --- | --- |
| Ramp `00..0f`, 16 B | `732780382ca3157581b95dc50e78053a` |
| All-zero preparation, 16 B | `7326823b28a6137289b057ce02750b35` |
| Ramp with preparation byte 0 XOR `0x80`, 16 B | `f32780382ca3157581b95dc50e78053a` |
| Ramp, 32 B | `732780382ca3157581b95dc50e78053ac5b7fff067cc57fe31ab3e8518dc03f3` |
| All-zero preparation, 32 B | `7326823b28a6137289b057ce02750b35c5b7fff067cc57fe31ab3e8518dc03f3` |

The ramp/zero output XOR is `00..0f` for the first block, followed by 16 zero bytes in the 32 B case. The one-byte control changes only the corresponding first output byte by `0x80`. Moving the ramp to the separate address preserves the earlier ramp output; volatile clobber does too. These experiments establish the finite relation and remove the earlier preparation/message alias. They do not prove arbitrary preparation linearity or a standard chaining mode.

## Source-lifted constructor and canonical model [WS1,WS4-WS6]

The straight-line constructor `[0x1b69c4,0x1b6a54)` contains 36 original instructions. The outer source loop supplies each counter i=0..255 exactly once. The original stores are `0x1b6a38` to first allocation A+`0xf60` and `0x1b6a50` to second allocation A+`0xb34`, each indexed by the same byte permutation times 4. Each destination receives exactly 256 u32 stores, within its requested 1027/1031 B extent.

Define, with explicit width w:

```text
phi_m^w(x) = x XOR ((x AND m) << 1), modulo 2^w
BR_r(x)    = rotate each of the four u8 lanes of u32 x left by r
pi(i)      = ROL8(phi_low8(M)^8(i), r) XOR b
E(z)       = BR_r(phi_M^32(z)) XOR K
```

Every captured parameter class satisfies the source-specific normalization of shifts/masks to these rotations. The general triangular map is invertible: initialize x=y and repeat `x = y XOR ((x AND m)<<1)` for w-1 steps, at width w. Independent UNSAT obligations prove the u8 and u32 inverses. Together with rotation/XOR, this establishes that pi permutes all 256 byte indices and E permutes u32 words in the retained representations.

Let G be a fixed u8 permutation and L a fixed affine expansion into u32. The complete arrays are:

```text
workspace1[pi(i)] = E(L(G(i)))
workspace2[pi(i)] = (G(i) << 8) XOR 0x65 XOR Q
```

The source tables independently determine:

```text
G(i) = high8(load_u16(image+0x1af3fc0 + 2*(i XOR 0xce)))
L(G(i)) = (load_u32(image+0x166f4e0 + 4*(i XOR 0x8c))
           + (i XOR 0x9a7cd460) + 0x80551819) XOR 0x71ad47f5
```

The addition wraps at u32 width. Every source u16 has low byte `0x65`; the high-byte values, after the input XOR, cover every u8 value exactly once. The auditor checks all 1536 B of these two fixed source tables and all 256 canonical input indices. Source-lifted store/address obligations hold over arbitrary load values; these complete original tables then discharge the retained finite lookup domain.

The fixed affine expansion is `L(x)=0x1fc44805 XOR XOR(columns[j] where bit_j(x)=1)`. Bits are numbered from the least significant bit:

| j | U32 column |
| --- | --- |
| 0 | `0x0c87f872` |
| 1 | `0x109f32bf` |
| 2 | `0x55294a32` |
| 3 | `0xa6bac3d7` |
| 4 | `0x80b55471` |
| 5 | `0xc4596bd6` |
| 6 | `0xb175e165` |
| 7 | `0xdac764f9` |

All 256 equality checks pass. G's 256 B plus eight u32 columns, one u32 affine offset and the u8 literal `0x65` total 293 B of canonical table data. Per-phase encoding parameters are additional; this count is not a claim about serialized evidence size or the whole transform's specification. G SHA-256 is `d5c79b57d35ed544ad0bfc85109f8ba7116cdfb4b697fd9f1e3b7e575d17fd83`.

| Retained source phase | M, u32 | r | b, u8 | K, u32 | Q, u32 |
| --- | --- | --- | --- | --- | --- |
| Ramp preparation, 16 B | `0x73737373` | 5 | `0x0c` | `0x848cefeb` | `0x79283b95` |
| Zero preparation, 16 B | `0x72727272` | 4 | `0x23` | `0xcab51e42` | `0x3711ca3c` |
| Byte-0 flip, 16 B | `0x4f4f4f4f` | 6 | `0xda` | `0x1ba90a62` | `0xe60dde1c` |
| Ramp preparation, 32 B | `0x7d7d7d7d` | 0 | `0xb7` | `0xa8ae57e6` | `0x550a8398` |
| Zero preparation, 32 B | `0x7c7c7c7c` | 1 | `0x98` | `0xe697a64f` | `0x1b337231` |

The clobber control repeats the first parameter class and output. Source register/stack bindings for every class are retained in the audit. Thus changes in stored workspace words across these controls do not imply changes to the canonical substitution: undoing pi/E/Q recovers the same G/L values. This result concerns the constructor and its five captured phases, not all callers or arbitrary native initialization.

```text
original table32/table16 bytes
              |
     fixed canonical G: u8 -> u8
              |
       +------+--------------------+
       |                           |
 affine expansion L          shift left 8, XOR 65
       |                           |
 word encoding E               XOR Q
       |                           |
       +---- shared index pi ------+
                    |
      two source-produced workspaces
```

## Permutation structure and bounded standard comparison [WS1,WS6]

For every nonzero u8 difference d, the auditor counts all 256 values `G(x) XOR G(x XOR d)`. Across `255*256=65280` pairs, nonzero histogram cells have count 2 in 32130 cases and count 4 in 255 cases. The maximum differential count is 4. This is a complete finite property of this G, not an algorithm identifier.

The comparison reference is the forward substitution table and its inverse defined by [NIST FIPS 197-upd1, Table 4 and Section 5.3.2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf), DOI `10.6028/NIST.FIPS.197-upd1`. The fetched 1184436 B PDF has SHA-256 `62c86eb567f13edb8f71826e985da870b04ef6381634f303cdb16e84d47becd1`. All 256 extracted Table 4 values match an independent GF(2^8) inversion/affine construction. The offline auditor pins those reference values and regenerates them; it does not re-fetch the PDF.

For each forward/inverse reference and each u8 delta, the tested family is:

```text
G(i) = A(reference(i XOR delta))
A     = any affine u8 -> u8 map
```

The permutation reference makes the candidate output map unique. Its value at zero and the eight basis vectors determine every affine coefficient. Each of the 512 candidates has a retained counterexample; none matches G. This excludes that precise family. Arbitrary affine input transformations, other reference constructions and the whole transform's identity remain unresolved. No AES identity or exclusion follows for the complete routine.

## Validation, interfaces and bounded continuation

Fresh independent original-byte replay checks six complete caller profiles, 488136 visits, 63394 reads, 40562 writes, 21086 PAC models, 30 API/sequential-CASAL models, 182 state points and 24 child entries. All six declared malloc attempts succeed in private backing. The auditor reconstructs six initial CPU frames and 3313664 B each of initial/final sparse RAM. It rechecks the previous allocator/ARX/retirement oracles with the separate preparation fixtures. No source PC, child record or source-produced allocation result is substituted.

Sixteen new UNSAT obligations comprise three source-lifted load/store contracts, ten phase-normalization contracts, the u8/u32 triangular inverses and the preparation data slice. Twelve frozen source obligations are freshly UNSAT. All 3072 workspace words, 4096 preparation-byte cases, 256 canonical substitutions, 65280 differential pairs and 512 bounded standard-reference candidates are checked. Fresh SDK syntax-only assertions pass. The constructor lift covers all 36 instructions; surrounding original control and private-state bindings are separately checked by whole-caller replay.

Time/space is conservatively `O(C*(B+P*F+V*J+R)+256^2)` for replay, constructor/domain checks and differential enumeration, bounded at 150000 visits/profile. Each workspace reconstruction uses `O(256)` time/space; the fixed affine expansion uses eight conditional XOR terms. The general inverse needs w-1 fixed-width steps. SMT has a separate 30 s/query limit. These are reproducible finite/source proofs, not native runtime measurements.

The new preparation plane and workspaces are process-local private addresses. No retained profile calls Mach send/receive, port allocation, MIG reply-port handling or descriptor transfer. No incoming/outgoing native port identity, new emission site or daemon/kext pairing is added. No new IDA access or mutation occurs; original file/fixup evidence suffices for this increment. Native context initialization and admission remain unknown.

| Impact | Next investigation | Completion / falsification condition |
| --- | --- | --- |
| High | Reduce workspace consumers to canonical substitution/linear operations. | Undo the proven storage encodings at every read, preserve source phases and establish a compact complete block mapping. Constructor equivalence alone is insufficient. |
| High | Prove or reject a general first-block preparation-XOR contract. | Symbolically account for arbitrary preparation bytes and all affected source branches; retained vector differences are finite evidence. |
| High | Establish original context/selector/holder initialization and upstream record producers. | Require source stores and same-epoch valid backing before making native admission or ownership claims. |
| Medium | Classify G under broader input/output transformations. | Provide an explicit checked equivalence or bounded counterexamples; differential count 4 and the failed narrow family do not identify a cipher. |
| Medium | Join the remaining ARX and table stages. | Compare a compact complete oracle with original-source outputs across independent message, preparation and context inputs. |
| Low | Relate canonical local values to daemon/kext contracts. | Require an actual producer/consumer handoff and message epoch before assigning wire meaning or port/right identity. |

- **QG1**: No normative premise is required; claims concern source behavior and mathematical properties.
- **QG2**: WS1-WS6 state dependencies and falsification probes.
- **QG3**: Preparation/data separation, constructor semantics, canonical representation, control/state bindings, environmental/reference context and interface limits are covered.
- **QG4**: Byte extents, u8/u16/u32/u64 operations, rotations, modular sums, basis order and data-size calculation are explicit.
- **QG5**: Changing storage encodings is distinguished from canonical substitution changes. Universal source/load-interface proofs, captured phases and finite output controls retain their respective scopes.
- **QG6**: Pinned original bytes/fixups, complete independent replay, source lifts, retained solver queries and the fingerprinted primary standard provide provenance.
- **QG7**: Impact-ranked continuation preserves unresolved whole-transform mathematics, input role, initialization, admission, ownership and cross-level handoffs. The full goal remains active.
