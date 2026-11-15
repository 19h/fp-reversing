# fairplayd: executable core lookup graph and fixed control envelope

The inner block core has a source-derived, context-specialized 128-bit-to-128-bit model. Its 192 data lookups comprise sixteen byte lookups before the word-table network, 160 word lookups, and sixteen byte lookups after that network. A standalone evaluator computes the resulting sixteen bytes without executing target instructions or invoking a solver. The two retained contexts produce identical typed graphs despite 28 differing context bytes. Fourteen source queries cover 676 address and exit conditions; 156 changed-input source-model runs match the evaluator. The algorithm name, key interpretation, native caller admission and daemon-kext transaction pairing remain unknown. [CL1-CL6; CL-A1-CL-A6]

This establishes a nonlinear fixed-table block transform under the stated contexts. A four-point counterexample rejects an affine map over GF(2), including a fixed XOR mask or a byte permutation followed by such a mask. Neither the count of lookups nor their table geometry identifies a cipher, semantic round count, key size, mode, encryption/decryption direction or universal inverse. [CL3-CL5; CL-A2-CL-A5]

| Evidence | Primary provenance and scope |
| --- | --- |
| CL1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; original instruction and immutable table bytes, original format-12 fixups. |
| CL2 | [Record-input lineage](daemon_record_input_origin_report.md) and [block staging](daemon_block_staging_report.md), with pinned parent receipts. Their two retained conditional normal classes supply the source intervals and entry context. Prior complete caller admissions are not rerun. |
| CL3 | [Extractor](triage_evidence/recover_daemon_core_lookup.py), [checks](triage_evidence/daemon_core_lookup_checks.json.zst), and [standalone evaluator](triage_evidence/daemon_core_lookup_kernel.py). The source lift yields a shared typed expression DAG with explicit finite lookup cuts. |
| CL4 | [Auditor](triage_evidence/audit_daemon_core_lookup.py), [audit](triage_evidence/daemon_core_lookup_audit.json.zst): original-frame replay, fourteen UNSAT queries, original-byte/fixup checks, 156 source-versus-DAG vector runs, and falsification controls. |
| CL5 | [Publication verifier](triage_evidence/verify_daemon_core_lookup_publication.py): fresh extraction/audit, canonical query comparison and re-solving, exact owned manifest delta, original-input preservation and decoded path hygiene. |
| CL6 | [ABI](interface_abi_report.md), [ports](mach_ports_report.md), [foundational triage](foundational_triage_report.md). The selected phase is internal to the descriptor callee; its table indices and authenticated branch are not established transport selectors or port emissions. |

Decoded receipt SHA-256 values: `5661e892920d52fac2029d2bbc4b3189c884caa839dd93552c268eed293689c9` (CL3), `39495d6ba9b37d1113d3d7ceba4c8ec317baec96f1ed1277ec7d4344df87d460` (CL4).

## Core placement and memory interface

The selected source phase starts at `0x10010eabc` and ends with BRAA at `0x1001112bc`, an interval of 10244 B containing 2561 four-byte instructions. The first 2560 instructions are lifted; the last branch is checked as a logical edge. This is a flattened internal phase reached through the descriptor's `0x8205` continuation, rather than a newly established callable routine boundary. The enclosing descriptor callee remains `0x100411480`. [CL1-CL4; CL-A1-CL-A3]

```text
descriptor callee
       |
input XOR staging -> A[16] -> core phase 0x10010eabc -> B[16]
                              |                       |
                         192 lookups              output XOR staging
                              |                       |
                    fixed authenticated edge          v
                       0x100135758                    T[16]
```

The retained SP H is `0x680005f9b0`. A=H+0xd0=`0x680005fa80`; B=H+0xe0=`0x680005fa90`. Their extents are each 16 B and they are disjoint. The source reads every A position once and writes every B position once. The audit proves the fixed addresses under arbitrary input bytes and arbitrary values returned by the explicit lookup cuts. This is a fixed-coordinate source-memory contract; it does not establish native allocation, object ownership, arbitrary placement or alias admission. [CL2-CL5; CL-A2-CL-A4]

| Input offset | Source read PC | Output offset | Source store PC |
| --- | --- | --- | --- |
| 0 | `0x10010efec` | 0 | `0x100111250` |
| 1 | `0x10010f0cc` | 1 | `0x100110e40` |
| 2 | `0x10010ee34` | 2 | `0x1001110c0` |
| 3 | `0x10010ee0c` | 3 | `0x100110ed4` |
| 4 | `0x10010ed54` | 4 | `0x100111118` |
| 5 | `0x10010f080` | 5 | `0x100110c70` |
| 6 | `0x10010f170` | 6 | `0x1001111d4` |
| 7 | `0x10010f194` | 7 | `0x1001111a0` |
| 8 | `0x10010ef80` | 8 | `0x100111054` |
| 9 | `0x10010efac` | 9 | `0x100110d60` |
| 10 | `0x10010ef2c` | 10 | `0x10011117c` |
| 11 | `0x10010ec8c` | 11 | `0x1001111f8` |
| 12 | `0x10010eedc` | 12 | `0x10011114c` |
| 13 | `0x10010eebc` | 13 | `0x100111014` |
| 14 | `0x10010f05c` | 14 | `0x100111280` |
| 15 | `0x10010ee8c` | 15 | `0x1001110e8` |

The table aligns offsets for compact site lookup; it does not assert that input j independently produces output j. Actual store order is `5,9,1,3,13,8,2,15,4,12,10,7,6,11,0,14`. The source expressions for these addresses contain data-derived terms; the universal store-address query proves their cancellation even when all lookup return values are independent symbolic words/bytes. [CL3-CL5; CL-A1-CL-A4]

The final dispatch load at `0x1001112b4` has a fixed address under the same premises. BRAA at `0x1001112bc` selects logical target `0x100135758` and modifier `0x5277`. The final dispatch is outside the 192 data lookups. No call instruction, Mach message operation or IOKit API occurs within this source interval. Hardware pointer authentication and the target's native execution are unexecuted. [CL1-CL5; CL-A1-CL-A3,CL-A6]

## Lookup tables and executable representation

Each reference window has 256 entries. Byte entries are u8; word entries are little-endian u32. Every dynamic lookup is proved to use an index in 0..255 and an address exactly equal to `base + entry_bytes*index`. The sixteen windows total `8*256 B + 8*1024 B = 10240 B`. All bytes are checked against the original image in each retained context. [CL1,CL3-CL5; CL-A1-CL-A4]

| Window base | Placement in source data flow | Entry width | Reads per context | Distinct raw values |
| --- | --- | --- | --- | --- |
| `0x100ed2340` | Before word network | 1 B | 4 | 160 |
| `0x101006fc0` | Before word network | 1 B | 4 | 256 |
| `0x100e9ede0` | Before word network | 1 B | 4 | 256 |
| `0x100e31270` | Before word network | 1 B | 4 | 256 |
| `0x100e40e10` | Main word network | 4 B | 36 | 256 |
| `0x100f33b10` | Main word network | 4 B | 36 | 256 |
| `0x100fdec70` | Main word network | 4 B | 36 | 256 |
| `0x100e94720` | Main word network | 4 B | 36 | 256 |
| `0x100f400e0` | Final word group | 4 B | 4 | 256 |
| `0x100ed3a70` | Final word group | 4 B | 4 | 256 |
| `0x100f2e680` | Final word group | 4 B | 4 | 203 |
| `0x10101ab70` | Final word group | 4 B | 4 | 256 |
| `0x100f28b60` | After word network | 1 B | 4 | 256 |
| `0x100fd6530` | After word network | 1 B | 4 | 256 |
| `0x100e6c8f0` | After word network | 1 B | 4 | 256 |
| `0x100e55890` | After word network | 1 B | 4 | 256 |

These are raw table cardinalities. The source combines table results with other values and index-derived arithmetic. The 160-value byte window and 203-value word window therefore do not establish that the complete transform loses information. Conversely, 256 distinct entries in another window do not prove that the whole transform is bijective. The source's interleaved scheduling and arithmetic remain encoded in the graph; a semantic round decomposition is unknown. [CL3-CL5; CL-A4-CL-A5]

The common graph has 14007 shared expression nodes, sixteen input variables, 192 lookup nodes and sixteen output roots. Literal values, widths and operation parameters are explicit. Node widths specify modular bit-vector arithmetic; concatenation and extraction retain exact byte/bit ordering. The evaluator uses integer arithmetic with width masks and performs each lookup from its captured window. It consumes no source instruction stream and imports neither the source lift nor Z3. [CL3-CL5; CL-A1-CL-A4]

```text
bind 16 input-byte nodes
for lookup in source dependency order:
    index = evaluate_shared_DAG(lookup.index)
    require 0 <= index < 256
    bind lookup.value = LE(window[entry_bytes*index : entry_bytes*(index+1)])
for output root:
    B[fixed_offset] = evaluate_shared_DAG(root)
```

For a graph with N nodes, E operand edges, L lookup nodes and W reference bytes, evaluation uses O(N+E+L+W) time and O(N+E+W) space. A shared-node cache prevents repeated expansion of the source's obfuscated subexpressions. [CL3-CL5]

Use `transform(case, input_bytes)` from `daemon_core_lookup_kernel.py`, where `case` is a decoded checks-receipt case and input_bytes has length 16. It returns the sixteen-byte result and ordered lookup PCs/addresses/values. The checks receipt pins the source, parents and extraction dependencies; the audit additionally pins the evaluator and its own dependencies. These pins and the address/exit certificates qualify use of this context-specific evaluator. [CL3-CL5; CL-A1-CL-A4]

## Context, verification and falsification

Each source phase has 300 ordered reads and 36 writes. The reads comprise 192 data lookups, sixteen input-byte reads, eighteen reads served by earlier phase stores, and 74 fixed-address reads. Of those 74 fixed read events, 26 use retained context values, 27 match original image bytes and 21 are original fixup targets. Their deduplicated incoming context comprises 272 bytes. The classes differ in 28 of those bytes; entry GP/SP register values agree and both generated graphs are identical. This proves common specialization for these two contexts, without an all-controller or all-placement theorem. [CL3-CL5; CL-A1-CL-A4]

| Query group | Conditions per context | Established source property |
| --- | --- | --- |
| Fixed read addresses | 74 | Literal/context/fixup reads use their captured cells |
| Store addresses | 36 | Twenty auxiliary stores and sixteen output stores use fixed cells |
| Input read addresses | 16 | Reads cover the sixteen input positions exactly once |
| Lookup extent and stride | 192 | Every data read stays in its 256-entry window at the correct stride |
| Reads of earlier stores | 18 | Byte-shadow substitutions address the certified prior stores |
| Exit target | 1 | Logical branch target is `0x100135758` |
| Exit modifier | 1 | Logical branch modifier is `0x5277` |

There are 338 conditions per context, 676 total. Seven grouped queries per context are nonvacuous and UNSAT. Input bytes and all lookup return values are independent symbolic bit vectors; image lookups are concretized only in the executable graph/evaluation. This overapproximation strengthens the address/exit checks: they do not require correlated or specially chosen table results. Conditions for shadow reads and stores qualify replacing their dynamic addresses by the captured cells. The final control read and edge remain separate from the data graph. [CL3-CL5; CL-A1-CL-A4]

Original-frame replay checks 5122 visits, 163968 GP/SP values, 5124 NZCV frames, 600 reads, 72 writes and two logical edges. It checks all original instruction words and all retained intermediate scalar states. The fixup auditor independently decodes the original words and checks 21 used format-12 pointer slots. This validates logical fixup interpretation without executing hardware authentication. [CL1,CL4-CL5; CL-A1-CL-A3]

For context 2, the changed-input corpus contains the retained input, zero, all-ones, an ascending byte ramp, all 128 single-bit inputs, and sixteen deterministic SHA-256-derived blocks: 148 distinct inputs. Context 3 repeats eight inputs, including four derived blocks. The 156 source-model runs lift 399360 instructions and compare all 2496 output bytes and 29952 ordered lookup values/addresses with the standalone evaluator. These are finite crosschecks of separate evaluation paths; the source lift and graph construction share instruction-semantics provenance. They are not independent native executions or a separately recovered reference algorithm. [CL4-CL5; CL-A1-CL-A5]

| Retained vector | Hexadecimal bytes |
| --- | --- |
| A[16], staged core input | `aa654fc05c04d85ac3b5a890a103a2ee` |
| B[16], core result | `f259a66c1840dc815c37b7405f22821f` |

The four-point control uses inputs `00...00`, `01 00...00`, `02 00...00`, and `03 00...00`. Their four outputs XOR to `ef5c3919718a79c728e64ff18e5a176b`, which is nonzero. An affine GF(2) map would yield zero, so this is an exact counterexample for the context-specialized model. A separate corrupted-reference control flips bit0 of byte `0x100e40fe0` in a copied literal table. The retained result changes from `f259a66c1840dc815c37b7405f22821f` to `6902f8cd2588f3e5a55f54a3f331daab`. The original image and published reference window remain unchanged. [CL4-CL5; CL-A1-CL-A5]

| Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- |
| CL-A1: Pinned source, parent receipts, instruction semantics and graph operators apply | Source coordinates, executable graph, numeric results and proofs | Rehash dependencies; regenerate the graph; replay every retained scalar frame; recheck canonical queries and original table/fixup bytes. Use another ISA implementation or native reference to reduce shared-model uncertainty. |
| CL-A2: The retained entry registers and fixed read-value contexts apply | Conditional 128-bit input/output model | Recover authentic caller objects, controller epochs and permissible placements. Two contexts and 28 differing bytes do not exhaust native environments. |
| CL-A3: Logical fixup and branch treatment applies | Fixed exit and internal continuation | Decode original pointer words and diversity metadata; verify authentic caller/return lifetime and hardware PAC separately. |
| CL-A4: Certified address cuts, fixed cell preservation and immutable windows apply | Total finite lookup evaluation and fixed sixteen-byte envelope | Reprove all 676 conditions; check stride/extents, byte-shadow congruence, input/output disjointness and all sixteen literal windows. Arbitrary native aliasing or mutation requires new premises. |
| CL-A5: Source specialization is distinguished from algorithm classification | Nonaffinity and bounded routine function | Check complete outputs and lookup ledgers; recover semantic state encodings and an independent reference before assigning cipher/key/mode/inverse semantics. Raw table collisions alone do not decide whole-function invertibility. |
| CL-A6: Private source data flow is distinguished from native transport | No new port right, Mach emission or daemon-kext transaction mapping | Join authentic caller/consumer objects and port/right histories to a matched native daemon-kext exchange. Current source continuation addresses do not establish that join. |

Reproduction in the established Python/Z3 environment runs `recover_daemon_core_lookup.py`, then `audit_daemon_core_lookup.py`; after manifest refresh run `verify_daemon_core_lookup_publication.py`. The evaluator itself requires only Python integer operations. Nontrivial receipts use `zstd --ultra -22 -q -T1` with decoded roundtrip/hash checks. Extraction uses O(parent bytes + source visits + expression DAG + reference bytes) time/space; retained replay adds O(32*5122), changed-input source lifting O(156*2560), and graph evaluation follows the bound above. Solver search is additional, limited to 30 s per query. [CL3-CL5]

| Impact | Bounded continuation | Required evidence |
| --- | --- | --- |
| High | Recover semantic state layers and identify the block primitive | Normalize the encoded state/table functions; certify dependency cuts; compare complete vectors with an independently specified algorithm. |
| High | Generalize context and native admission | Establish how actual callers populate the 272-byte context, select literal windows and preserve object/stack ownership. |
| High | Connect the transformed result to the daemon-kext interface | Recover actual result consumers and a matched native transaction with port/right and IOKit call histories. |
| Medium | Determine full invertibility | Prove whole-state layer bijections or find a whole-function collision; raw window cardinalities are insufficient. |

**QG1**: Factual technical scope. **QG2**: CL-A1 through CL-A6 register dependencies and falsification probes. **QG3**: Source-phase placement, executable data graph, fixed memory/control envelope, literal windows, nonlinear behavior and transport boundary are covered for this increment; the full goal remains active. **QG4**: Bit widths, byte units, endian order, extents, counts and complexity are explicit. **QG5**: Raw table cardinalities versus whole-function properties, fixed specialization versus native admission, data lookups versus final dispatch, and finite crosschecks versus universal address proofs are distinguished. **QG6**: Original instruction/table/fixup bytes, retained frame replay, source proofs, independent DAG operators and pinned receipts provide provenance with the shared-model limitation stated. **QG7**: Impact-labelled continuation is bounded above. All gates pass for this increment; algorithm identity and native transport remain unknown.

## Core affine-table follow-up

The [affine-table increment](daemon_core_affine_report.md) establishes the initial sixteen byte/index codecs and exact forward AES S-box and encoded MixColumns identities for the four main word tables. Source projections, complete finite domains and explicit rejection witnesses qualify these component contracts. Full round/key semantics and the native daemon-kext transaction join remain unknown.

## Core round-composition follow-up

[The nine-layer composition report](daemon_core_rounds_report.md) proves the source consumer equations for all nine main substitution/ShiftRows/MixColumns layers and all sixteen terminal word indices. The source interleaves layers and terminal/output lookups. Eight recovered offset vectors exactly match an AES-128 expansion subsequence, giving a nine-layer encryption prefix under an explicit core input whitening. Final decoding, full encryption equivalence and native daemon-kext/material correspondence remain unknown; assumptions, source proofs and independent checks are retained there.
